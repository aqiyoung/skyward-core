# 04 · 协议层

协议是最大的那块（`transport` 71,833 行），也是唯一不能靠"重写会更好"说服人的部分：**每个协议都必须与现有服务端互通**，没有第二条路。所以这一份的原则是：**先翻译，再优化；先对拍，再重构。**

## 1. 全清单与分档

Go 版的 28 种出站（`adapter/parser.go` 的 switch）、20 种入站（`listener/parse.go` 的 switch）。按"用的人多少 × 实现难度"分四档：

### P0 — 第一批（M2–M3）

| 协议 | 出站 | 入站 | Go 行数（out+transport） | Rust 依赖 | 风险 |
| --- | --- | --- | ---: | --- | --- |
| Direct / Reject / RejectDrop / Dns / Rematch / Pass | ✓ | — | 小 | 无 | 低 |
| SOCKS5（含 UDP assoc） | ✓ | ✓ | 502 | 自写（RFC 1928） | 低 |
| HTTP / HTTPS（CONNECT） | ✓ | ✓ | 257 + listener | 自写 + hyper | 低 |
| Shadowsocks（AEAD，含 2022） | ✓ | ✓ | 525 + 1,153 | `aes-gcm`、`chacha20poly1305`、`blake3` | 中：2022 的 PSK/时间戳/EIH 细节 |
| Trojan | ✓ | ✓ | 403 + 242 | rustls | 低，但 UDP 帧格式要逐字节对 |
| VMess（AEAD） | ✓ | ✓ | 678 + 1,751 | 自写 AEAD 头 + `md-5`/`sha1` | 中：`alterId=0` 之外要兼容旧服务端 |
| VLESS | ✓ | ✓ | 918 + 2,442 | 自写头 + rustls/reality | 中：encryption(ML-KEM) 是可选增强 |
| ShadowsocksR | ✓ | — | 245 + 2,082 | 自写（协议/混淆插件） | 中：混淆插件多，先做 `origin`/`plain` |
| Snell | ✓ | ✓ | 328 + 3,396 | 自写 + `chacha20poly1305` | 中高：v3/v4/v5/v6 多版本，无公开规范，只能对照代码 |
| WireGuard | ✓ | — | 887 + boringtun 等价物 | `boringtun` 或自写 noise | 中高：需要 L3 栈 |

### P1 — 第二批（M4）

| 协议 | 备注 |
| --- | --- |
| TUIC v5 | 基于 quinn；拥塞控制 BBR 是 Go 版自写（`transport/tuic/congestion*` 共 8.5k 行），第一版用 quinn 的 cubic 即可，BBR 后置 |
| Hysteria2 | QUIC + 自定义拥塞（`transport/hysteria/congestion`）；需要 UDP `brutal` |
| AnyTLS | `transport/anytls`（2.4k）有 padding 与多路复用，Rust 版可先用单路 |
| Socks4 | 200 行，顺手做 |
| HTTP/2、WebSocket、gRPC 传输 | 作为**传输装饰器**，对所有协议可用 |

### P2 — 按需（M5+）

`shadowtls`（1.9k）、`shadowquic`（1.8k）、`masque`（686）、`jls`（1.3k）、`restls`（83）、`mekya`（1.6k）、`mkcp`（1.7k）、`kcptun`（484）、`v2ray-plugin`（260）、`simple-obfs`（571）、`gost-relay`（565）、`xhttp`（3.3k）、`tlsmirror`（3.0k）、`trusttunnel`（1.3k）

### P3 — 挂起（不在 Rust 版计划内）

`openvpn`（13.5k）、`sudoku`（13.6k）、`mieru`（自带完整协议栈）、`easytier` / `tailscale` / `zerotier`（各带一个 mesh VPN 运行时）。

理由：这六项合计约 32k 行 Go、依赖重、用户面窄，且都是"独立产品级"实现。Rust 版通过 feature gate 明确不支持，并在配置加载时报错给出建议（见 §8）。

## 2. 分层：线与协议分离

Go 版把两者混在一起：`adapter/outbound/vless.go` 里既有协议头，又有 `ws / grpc / h2 / xhttp / reality / shadowtls` 的传输选择（看 `StreamConnContext` 那个 200 行的 switch 就知道了）。

Rust 版强制分成两层：

```
        ┌──────────────────────────────────────────────┐
        │ Proxy (skyward-proxy)                        │
        │   Vless::connect()                           │
        │     1. 选 transport -> 2. 拿到 AsyncStream   │
        │     3. 写协议头 -> 4. 返回 Conn              │
        └───────────────┬──────────────────────────────┘
                        │
        ┌───────────────▼──────────────────────────────┐
        │ Transport (skyward-transport)                │
        │   Direct | Tls | Ws | H2 | Grpc | HttpUpgrade│
        │   Reality | ShadowTls | Restls | Jls         │
        │   每个都是 AsyncStream -> AsyncStream 的包装  │
        └──────────────────────────────────────────────┘
```

`Transport` 是 async 函数指针链，不是 trait 对象：

```rust
// crates/skyward-transport/src/lib.rs
pub enum TransportKind {
    Direct,
    Tls(TlsOptions),
    Ws(WsOptions),
    H2(H2Options),
    Grpc(GrpcOptions),
    HttpUpgrade(UpgradeOptions),
    Reality(RealityOptions),
    ShadowTls(ShadowTlsOptions),
    Restls(RestlsOptions),
    Jls(JlsOptions),
}

pub struct TransportChain(pub SmallVec<[TransportKind; 2]>);

impl TransportChain {
    pub async fn connect(&self, ctx: TransportCtx, base: Box<dyn AsyncStream>) -> Result<Box<dyn AsyncStream>, Error> {
        let mut s = base;
        for step in self.0.iter() {
            s = match step {
                TransportKind::Direct => s,
                TransportKind::Tls(o) => tls::wrap(s, o.clone()).await?,
                TransportKind::Ws(o)  => ws::wrap(s, o.clone(), &ctx).await?,
                // ...
            };
        }
        Ok(s)
    }
}
```

好处很直接：**新增一个协议只需要实现"握手 + 帧化"，不必再写一遍 WS/H2/Reality**。Go 版每个协议都要重复那段选择逻辑，这也是 `adapter/outbound/vmess.go` 678 行、`vless.go` 918 行的原因。

## 3. TLS 与指纹伪装

Go 版依赖 `metacubex/utls`（uTLS 分支），用途是让 ClientHello 看起来像 Chrome/Firefox。这在现实中有实际作用（部分服务端会按 JA3 拒绝默认 Go TLS）。

Rust 侧的现实情况：

| 方案 | 能否伪装指纹 | 代价 |
| --- | --- | --- |
| `rustls` | 不能（ClientHello 固定，扩展顺序与 cipher 列表由 rustls 决定） | 纯 Rust，易交叉编译，`ring`/`aws-lc-rs` |
| `boring`（BoringSSL 绑定） | 能，通过 `SslConnector` + 自定义 `ClientHello` 回调 | 需要 cmake + C 工具链；Android NDK 与 iOS 需单独构建 |
| `rustls` + 自定义 `ClientHello` | 部分（可改 cipher suites / 扩展 / GREASE，但无法复刻完整指纹） | 需要 fork `rustls` 的 `ClientConfig` 生成路径 |

**决策**：默认用 `rustls`；`client-fingerprint` 配置项存在时切换到 `boring`（feature `utls`）。这两条路径在 `skyward-transport/src/tls.rs` 后面，调用方只看到 `TlsOptions { fingerprint: Option<Fingerprint> }`。

Reality 必须在 `boring` 或自写 X25519 握手上做（它要改写 ClientHello 的 key_share 并对 server 证书做 HMAC 校验）。第一版 Reality 只做 `boring` 后端。

## 4. 逐协议要点

### Shadowsocks

- 2022 版（`2022-blake3-aes-128-gcm` 等）与旧 AEAD 并存。Go 版 `transport/shadowsocks/core` + `shadowaead` + `shadowstream` 三层。Rust 版对应 `ss/aead.rs`、`ss/stream.rs`、`ss/blake3.rs`。
- **地址头**：AEAD 的 ATYP/ADDR/PORT 在加密载荷内；2022 版在首个 chunk 里，且带 padding 长度。
- **UDP**：每个包 = `[salt][AEAD(addr+payload)]`。
- 复用现成 crate（`shadowsocks-crypto`）可以做，但它绑定了自己的 `ProxyStream` 抽象；**建议自写 AEAD 层**（不到 400 行），以便接入我们的 `TransportChain`。

### Trojan

- 握手：`hex(sha224(password)) \r\n CMD SOCKS5Addr \r\n`，然后直接透传。
- UDP：`SOCKS5Addr + len(u16) + \r\n + payload`，`maxLength = 8192`。
- 注意 Go 的 `KeyLength = 56`（sha224 十六进制）。

### VMess

- AEAD 头：`md5(cmdkey + uuid + 16字节随机)` 派生，指令块用 AES-128-CFB / ChaCha20 加密。
- 响应头校验：`sha256(authid + 4字节)`。
- 请求体：`[len(u16)][masked][AEAD tag]`，每个 chunk 独立 nonce 递增。
- **实战建议**：先用 Go 版的 `test/` 协议测试套件（Docker + 自建服务端）跑通互通，再谈性能。Go 仓库里 `listener/inbound/vmess_interop_test.go` 就是这类测试，可照着写 Rust 的。

### Snell

没有公开规范，只能读 `transport/snell/{v4,v6}.go`。要点：

- v3 之后的 AEAD 与 v4 的 `snell://` 混淆、v5/v6 的 profile（`v6_profile.go`）。
- 建议**直接对照 Go 代码逐函数翻译**，并且每个版本都保留一个 Go 生成的测试向量（见 09 §6）。

### TUIC / Hysteria2

- 两者都基于 QUIC，但拥塞控制不同。quinn 允许自定义 `congestion::Controller`；先实现一个简单的 `cubic` 包装，BBR 从 Go 版 `bbr_sender.go`（1,009 行）翻译。
- QUIC 的 0-RTT、`disable-sni`、`udp-over-stream` 都要显式开关，不要默认开启。

### WireGuard

- Rust 侧 `boringtun` 提供 noise 握手与加解密，但**不含 IP 栈**。Go 版用 `mipstack` / `sing-wireguard` 提供 L3。Rust 版需要用 `smoltcp`（no_std 友好、纯 Rust）作为 IP 栈，或自己写一个最小栈。
- 这是唯一需要"引入一个 IP 栈"的协议，工作量应按"周"而不是"天"估。

## 5. 入站

入站的复杂度分布与出站相反：**协议简单，但"必须同时对外提供正确的错误响应"**。

| 入站 | 要点 |
| --- | --- |
| HTTP | CONNECT / 普通请求 / 认证（`Proxy-Authorization`）；`allow-lan` 时绑定 `0.0.0.0`；`skip-auth-prefixes` 按源 IP 跳过认证 |
| SOCKS | 同时支持 v4/v5，UDP ASSOCIATE 要回 `BND.ADDR`；认证用 RFC 1929 |
| Mixed | 首字节嗅探：`0x05` → SOCKS5，其余 → HTTP；不能预读超过 1 字节并丢失 |
| TUN | 见 §7 |
| Redir / TProxy | 从 `SO_ORIGINAL_DST` / `IP_TRANSPARENT` 取原始目标；Linux only |
| Shadowsocks / Trojan / VMess / VLESS 入站 | 与出站对称，但要处理"多人多密码"与 `users` 表 |
| Tunnel（`tunnels` 配置） | 本地端口 → 远端地址的点对点转发，不经过规则 |

入站的**统一外壳**（Go 的 `listener/inbound/base.go`）：

```rust
pub struct BaseInbound {
    pub listen: String,           // "0.0.0.0:7890"
    pub bind_address: String,     // allow-lan / bind-address 解析结果
    pub udp: bool,
    pub tfo: bool,
    pub mptcp: bool,
    pub users: Vec<AuthUser>,
    pub special_rules: Option<String>,
    pub special_proxy: Option<String>,
    pub in_name: String,
}
```

`in_name` 会出现在规则里（`IN-NAME` 规则）与 API 的 `metadata.inboundName`，默认值必须与 Go 一致：`"DEFAULT-MIXED"`、`"DEFAULT-HTTP"` 等。

## 6. 认证与用户

Go 的 `component/auth` + `listener/auth` 提供：

- `AuthStore`：全局用户名/密码表，支持"每用户独立"从入站配置追加。
- `skip-auth-prefixes`：按源 IP 段跳过认证（默认 `127.0.0.1/8`、`::1/128`）。
- `lan-allowed-ips` / `lan-disallowed-ips`：黑名单优先。

Rust 版把这些做成 `InboundPolicy`，在 accept 之后、协议解析之前执行；错误码必须逐字对齐（SOCKS5 `0x02`/`0x05` 回复，HTTP `407`），否则客户端行为会变。

## 7. TUN

Go 版有四个栈：`gVisor`、`System`、`Mixed`、`Mips`，外加实验性的 `Go` 栈（`-tags with_go_stack`）。Rust 版方案：

| 层 | 方案 |
| --- | --- |
| 设备打开 | Linux `ioctl(TUNSETIFF)`；macOS `utun` 控制 socket；Windows Wintun（`wintun.dll` 动态加载）；Android 用宿主传入的 fd |
| IP 栈 | `smoltcp`（TCP/UDP/ICMP 都有），或 `netstack-smoltcp` |
| 路由/MTU/地址 | 由宿主做（与 Go 版一致：CLI 模式下不自动开 TUN） |
| DNS 劫持 | 栈内识别 53 端口并交给 `skyward-dns` |

**代价要说清楚**：`smoltcp` 的 TCP 是"够用"级，高吞吐下的窗口缩放与 SACK 不如 gVisor。这与 Go 版已有的"go stack（sing-tun Go 实现）vs gVisor"的取舍是同一个问题。建议 M5 时用仓库里现成的 `bench/tunnel_bench.sh` 对两者做同机对比，把结论写进 10 的基准表。

## 8. 不支持的协议怎么报错

配置里出现 Rust 版未实现的协议时，**不能静默忽略**（Go 版的 `parser.go` 遇到未知类型会报错）。错误信息要可操作：

```json
{
  "message": "proxy \"hk-01\": type \"sudoku\" is not supported by this build (available: ss, trojan, vmess, vless, socks5, http)",
  "path": "proxies[3].type"
}
```

实现方式：`ProxyKind` 枚举里保留全部 29 个名字（保证能解析、能报错、API 能展示），但 `build_proxy` 只对启用的 feature 返回 `Ok`。

## 9. 互通测试怎么搞

**不要为 Rust 版单独搭服务端**。仓库已有：

- `test/` 下的 Go 协议测试（Docker 起 shadowsocks/vmess/trojan/snell 服务端，跑 pingpong 与大数据）。
- 各出站的 `*_test.go`（如 `listener/inbound/vmess_interop_test.go`）本身就能充当"参考实现"。

做法：写一个 `xtask interop`，用 Docker Compose 起同一批服务端，然后**两个客户端都指向它**：Go 版作为基准，Rust 版作为被测对象；对同一组用例（TCP pingpong、UDP pingpong、64MiB 传输、错误密码、错误地址）比较**字节级结果**而不是"成功/失败"。

这项在 M2 就必须建立，否则到 M4 会发现协议实现"能连但不时断"，而那时已经写了三四个协议。
