# 09 · 逐包移植手册

写给真正动手的人。每一条都是"Go 这么写，Rust 应该这么写"，并指出**语义会变的地方**。

## 1. `constant/metadata.go` → `skyward-core::model::metadata`

### Go

```go
type Metadata struct {
    NetWork  NetWork  `json:"network"`
    Type     Type     `json:"type"`
    SrcIP    netip.Addr
    DstIP    netip.Addr
    Host     string
    DstPort  uint16
    DNSMode  DNSMode
    // ...
}

func (m *Metadata) RuleHost() string {
    if m.Host != "" { return m.Host }
    if m.DstIP.IsValid() { return m.DstIP.String() }
    return ""
}

func (m *Metadata) Valid() bool {
    if m.Host == "" && !m.DstIP.IsValid() { return false }
    return m.DstPort != 0
}
```

### Rust

```rust
impl Metadata {
    pub fn rule_host(&self) -> Cow<'_, str> {
        match &self.host {
            Some(h) => Cow::Borrowed(h),
            None => match self.dest {
                Dest::Domain { ref host, .. } => Cow::Borrowed(host),
                Dest::Ip { ip, .. } => Cow::Owned(ip.to_string()),
            },
        }
    }

    pub fn is_valid(&self) -> bool {
        let has_target = self.host.is_some()
            || matches!(self.dest, Dest::Domain { .. } | Dest::Ip { .. });
        has_target && self.dest.port() != 0
    }
}
```

**陷阱**：`Cow::Owned(ip.to_string())` 每次匹配 IP 规则都分配。规则里的 IP 规则直接读 `dest.ip()`，**不要**用 `rule_host()` 去解析字符串再转回 IP。Go 也是这么做的（`IPCIDR.Match` 读 `metadata.DstIP`）。

### `netip.Addr` v.s. `IpAddr`

Go 的 `netip.Addr` 有"零值"（invalid）语义，Rust 的 `IpAddr` 没有。凡是 Go 里判断 `.IsValid()` 的地方，Rust 用 `Option<IpAddr>`。**不要**用 `IpAddr::V4(Ipv4Addr::UNSPECIFIED)` 当零值——那是合法地址 `0.0.0.0`。

## 2. `tunnel/tunnel.go` → `skyward-core::tunnel`

### 正则与 IP 的惰性解析

Go：

```go
helper := C.RuleMatchHelper{}
if metadata.NetWork == C.UDP && !adapter.SupportUDP() { continue }
matched, ada := rule.Match(metadata, helper)
```

而 `RuleMatchHelper.ResolveIP` 是在 `resolveMetadata` 里按需赋值的：

```go
helper := C.RuleMatchHelper{
    ResolveIP: func() { /* 解析 metadata.Host -> DstIP */ },
}
```

Rust：

```rust
let mut resolved = false;
let resolve = |m: &mut Metadata| {
    // 阻塞解析：需要 async，因此在调用前先完成
};

// 更好的写法：把"可能需要的解析"提前成一次 future
let need_ip = snap.rules.might_need_ip();
if need_ip && m.dest.is_domain() {
    let ip = dns.resolve(&m).await?;
    m.dest = Dest::Ip { ip, port };
}
let hit = snap.rules.matches(&m);
```

**这是移植中最大的语义陷阱**：Go 的 `ResolveIP` 是一个**副作用回调**，可以在匹配过程中多次调用（第一次生效）。Rust 里不可能在同步的 `matches()` 里 `.await`。两个解法：

1. **预解析**（推荐）：规则匹配前，如果 `m` 有域名且规则集含 IP 规则，先解析一次，把结果写进 `Metadata`。缺点是即使命中的是第一条 DOMAIN 规则也会付一次解析成本。
2. **两阶段匹配**：先跑不需要 IP 的规则（domain / port / process / 逻辑），若全都不命中且有 IP 规则，再解析后跑 IP 规则。**这与 Go 的语义完全等价**，因为 Go 的顺序扫描里 IP 规则之后的 domain 规则本来也不会被命中（一旦命中就返回）。

建议实现 (2)：

```rust
pub fn matches(&self, m: &mut Metadata, resolve: &mut dyn FnMut(&mut Metadata) -> Option<IpAddr>) -> Option<AdapterName> {
    // pass 1: 不含 IP 依赖的规则
    for rule in self.rules.iter().filter(|r| !r.needs_ip()) {
        if let Some(a) = rule.hit(m) { return Some(a.clone()); }
    }
    // 只有存在 IP 规则且还没解析时才解析
    if self.has_ip_rules() && m.dest.is_domain() {
        if let Some(ip) = resolve(m) { m.dest = Dest::Ip { ip, port: m.dest.port() }; }
    }
    // pass 2: 剩下的（按原始顺序！）
    ...
}
```

⚠️ 注意：pass 1 / pass 2 的拆分**必须保持"第一条命中"的语义**。不能简单地把所有非 IP 规则跑完再跑所有 IP 规则——因为规则列表是用户写的顺序，`IP-CIDR,x,DIRECT` 排在 `DOMAIN-SUFFIX,y,PROXY` 前面时，Go 会先看 IP 规则。正确做法是：**按顺序遍历，遇到第一条 IP 规则时才触发解析**（一次），之后所有规则都可正常评估。这才是唯一等价且不浪费的写法。

## 3. `component/dialer` → `skyward-core::net::dialer`

### Go

```go
func DialContext(ctx context.Context, network, address string, options ...Option) (net.Conn, error) {
    ips, port, err := parseAddr(ctx, network, address, opt.resolver)
    // 串行或并行尝试多个 IP
    // 每个 IP 用 net.Dialer{Control: ...} 绑定接口 / 打 mark / 设 TFO
}
```

### Rust

```rust
pub struct Dialer {
    resolver: Arc<dyn Resolver>,
    iface: Option<String>,
    routing_mark: u32,
    tfo: bool,
    mptcp: bool,
    concurrent: bool,
}

impl Dialer {
    pub async fn dial(&self, target: &Target) -> Result<TcpStream, Error> {
        let addrs = self.resolver.resolve(target).await?;
        if self.concurrent { self.dial_parallel(addrs).await } else { self.dial_serial(addrs).await }
    }

    fn socket(&self, addr: SocketAddr) -> Result<TcpStream, Error> {
        let sock = Socket::new(domain(addr), Type::STREAM, Some(Protocol::TCP))?;
        if let Some(iface) = &self.iface {
            #[cfg(target_os = "linux")]
            sock.bind_device(Some(iface.as_bytes()))?;
        }
        if self.routing_mark != 0 {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            sock.set_mark(self.routing_mark)?;
        }
        sock.set_nonblocking(true)?;
        // 转成 tokio 的 TcpStream
        let std_stream: std::net::TcpStream = sock.into();
        TcpStream::from_std(std_stream)
    }
}
```

要点：

- **`socket2` + `from_std`** 是标准做法，但 `from_std` 要求 socket 已 `set_nonblocking(true)`。
- 接口绑定：Linux `SO_BINDTODEVICE`、macOS `IP_BOUND_IF`/`IPV6_BOUND_IF`、Windows 没有等价物（只能选源地址）。**Go 版在 Windows 上是"忽略 interface 名"**，Rust 同样处理，不要报错。
- `routing-mark` 仅 Linux(Android)。
- TFO：Linux `TCP_FASTOPEN_CONNECT`，macOS `TCP_FASTOPEN`；用 `socket2` 的 `set_tcp_fastopen_connect`（需要较新版本）或 `libc` 直调。
- 并发拨号（`tcp-concurrent: true`）：所有地址同时拨，第一个成功的赢，其余 abort。**注意取消语义**：Go 用 `context` 取消；Rust 用 `JoinSet` + `abort_all`。

### 双栈回落

Go 的 `dualStackDialContext` 有个 300ms 的 `dualStackFallbackTimeout`：IPv4 与 IPv6 同时拨，但 IPv6 慢启动 300ms 后如果 IPv4 还没成功，就启动 IPv6。Rust 同样实现，否则在坏 IPv6 网络下用户会觉得"卡住 5 秒"。

## 4. `common/net` 的三个包装

这三个包装是 Go 版能用**统一 `net.Conn` 接口**串起所有协议的关键，Rust 版必须重新实现（每个约 50–100 行）：

```rust
// 1. BufferedConn：把已读入缓冲的字节放回流前面（嗅探后使用）
pub struct BufferedStream<S> {
    inner: S,
    buf: Bytes,     // 已经读出来但还没消费的字节
}
impl<S: AsyncRead + Unpin> AsyncRead for BufferedStream<S> {
    fn poll_read(...) {
        if !self.buf.is_empty() { /* 先吐 buf */ }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// 2. CachedConn：与 BufferedConn 类似，但用于"协议协商后剩余字节"
//    （例如 VMess 读响应头时多读的字节）

// 3. EarlyConn：握手延迟到第一次读写
pub struct EarlyStream<S, F> {
    inner: S,
    handshake: Option<F>,      // 只执行一次
}
impl AsyncRead for EarlyStream<S, F> {
    fn poll_read(...) {
        // 首次 poll 时先 poll handshake future
    }
}
```

**为什么需要 EarlyConn**：VLESS/VMess 的"响应头在第一次读时才到达"，而写端可能已经要先发数据（例如 TLS 内层的 HTTP/2 preface）。Go 版用 `earlyConn` 把"协商响应"推迟到第一次读写；Rust 版用 `poll_fn` + `Option<Pin<Box<dyn Future>>>` 实现同样的语义。

## 5. `component/sniffer` → `skyward-core::sniff`

Go 的三个嗅探器（TLS / HTTP / QUIC）。Rust 版第一版只做 TLS + HTTP：

```rust
pub async fn sniff_tls(buf: &[u8]) -> Option<&str> {
    // TLS record: [0] = 0x16, [1] = 0x03, [2] = 0x01..0x04
    // handshake type [5] = 0x01 (ClientHello)
    // 之后是 length(2) + version(2) + random(32) + session_id + cipher_suites + ...
    // 最后找 SNI 扩展（type 0x0000）
    // 建议直接用 tls-parser crate，或自己写约 120 行
}

pub async fn sniff_http(buf: &[u8]) -> Option<&str> {
    // 用 httparse 解析请求行和 headers，优先 Host，其次 :authority（HTTP/2）
    // HTTP/2 需要解析 h2 的 HEADERS 帧 + HPACK（Go 用 golang.org/x/net/http2/hpack）
}
```

要点：

1. **只读不消费**：嗅探必须通过 `BufReader::fill_buf()` + 不 consume，或用 `BufferedStream` 把字节放回。
2. **上限 64 KiB**（Go 的 `maxSniffBufferSize`），防止恶意流把内存撑爆。
3. **`force-domain` / `skip-domain` / `skip-src-address` / `skip-dst-address` / `force-dns-mapping` / `parse-pure-ip`** 六个策略开关都要保留，它们决定嗅探结果是否被采纳。
4. QUIC 嗅探（`quic_sniffer.go`）需要解析 QUIC Initial 包里的 CRYPTO 帧并解密，复杂度高；第一版用 Go 版的同样做法：**不做**，只在配置要求时警告。

## 6. 测试向量：把 Go 当作参考实现

协议翻译最怕"看起来对，实际上少写了一个字段"。做法：

```go
// test/gen_vectors_test.go （Go 版仓库里新增，只用于生成）
func TestGenVmessVectors(t *testing.T) {
    for _, c := range cases {
        buf := encodeWithReferenceImpl(c)   // 用现有 Go 代码编码
        writeFixture(fmt.Sprintf("vmess/%s.bin", c.Name), buf)
    }
}
```

然后 Rust 侧：

```rust
#[test]
fn vmess_matches_reference_vectors() {
    for entry in walkdir("fixtures/vmess") {
        let expected = std::fs::read(entry.path()).unwrap();
        let actual = vmess::encode_request(&decode_case(entry.path()));
        assert_eq!(actual, expected, "{}", entry.path().display());
    }
}
```

**注意**：这只能在"确定性的部分"用（固定 UUID、固定时间、固定随机数种子）。加密协议里有随机 nonce/盐，要注入可控随机源（`trait Rng`，测试时换成固定序列）。

## 7. 日志与错误信息的措辞

Go 版的日志有固定格式，面板可能会解析（尤其是错误行）。Rust 版用 `tracing` 格式化时保持形状：

```rust
// Go: log.Infoln("[TCP] %s --> %s match %s using %s", ...)
// Rust:
info!("[TCP] {} --> {} match {} using {}", src, dst, rule, proxy);
```

`/logs` 的 WebSocket 消息格式（`{type, payload}`）是硬约束。

## 8. 常见翻译错误清单

| Go 写法 | 错误译法 | 正确译法 |
| --- | --- | --- |
| `if err != nil { return }` 在 goroutine 里 | 用 `?` 传播（goroutine 没有返回点） | 显式 `if let Err = ... { log }` |
| `defer conn.Close()` | 期待 `Drop` 自动关 | 显式 `conn.close().await` 或用 scope guard |
| `sync.Mutex` 保护 map | `DashMap` 一把梭 | 只在真正高并发读写时用 `DashMap`；否则 `RwLock<HashMap>` 更可预测 |
| `time.AfterFunc` | `tokio::spawn` + `sleep` 忘了取消 | 用 `CancellationToken` + `select!` |
| `context.WithTimeout` | `tokio::time::timeout` 包住整个函数 | 注意超时后资源清理（连接需要 close） |
| `strings.ToLower` 比较域名 | 直接用（Unicode 大小写） | 域名用 `to_ascii_lowercase()`（DNS 是 ASCII） |
| `errors.Is(err, X)` | 字符串比较 | 用枚举 + `matches!` |
| `%v` 打印结构体 | `{:?}` 用于日志 | 用 `Display` 给用户，`Debug` 给开发 |
| `for k, v := range map` | 假设顺序 | Go 的 map 顺序随机；Rust 的 `HashMap` 也随机。**凡是有顺序要求的地方都要用 `IndexMap` 或显式排序** |

最后一条值得单独强调：Go 版 API 返回 JSON 时经常直接 `json.Marshal(map[string]any)`，键序由 encoder 排序（`encoding/json` 对 map 的 key 排序）。Rust 的 `serde_json` 对 `HashMap` **不排序**。这不影响 JSON 语义，但会让快照 diff 变得吵闹。建议响应里用 `IndexMap` 或 `serde_json::json!` 宏（保持书写顺序）。
