# 02 · 领域模型

这一份是 Rust 代码的"骨头"：类型与 trait。目标不是照抄 Go 的接口，而是让每个 Go 接口在 Rust 里有一个**代价合理、语义等价**的表达。

## 1. 读写路径的分界

Go 版很多接口在 Rust 里会分裂成两个：

| Go | Rust | 为什么 |
| --- | --- | --- |
| `C.ProxyAdapter.DialContext(ctx, *Metadata) (Conn, error)` | `Proxy::connect(&self, cx: &mut DialCtx) -> Result<Conn, Error>` + `Proxy::listen_packet(&self, cx) -> Result<PacketConn, Error>` | Rust 的 async trait 需要 `async-trait` 或 RPITIT；参数里的 `*Metadata` 会被修改（chains、RemoteDst），所以传 `&mut` 而不是 `&` |
| `C.Rule.Match(*Metadata, RuleMatchHelper) (bool, string)` | `Rule::matches(&self, m: &Metadata, h: &mut MatchHelper) -> MatchResult` | Go 用"返回 adapter 名字"来传递结果；Rust 直接返回 `enum MatchResult { No, Hit { adapter: AdapterName } }`，避免字符串分配 |
| `C.Tunnel` 接口 | `Tunnel` 具体类型 + `Arc<Snapshot>` | Go 是为了给 `inner` 包解耦；Rust 用 trait 只会带来 `dyn` 开销，改为具体类型 |
| `P.ProxyProvider` 接口 | `ProxyProvider` trait（对象安全） | 订阅有多种 vehicle（file/http/inline/compatible），必须动态 |

## 2. `metadata`

```rust
// crates/skyward-core/src/model/metadata.rs
use std::net::{IpAddr, SocketAddr};
use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network { Tcp, Udp }

/// Go 的 `C.Type`（入站来源），用于 INNER 过滤、规则与 API 展示。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnType {
    Http, Https, Socks4, Socks5,
    Shadowsocks, Snell, Vmess, Vless,
    Redir, Tproxy, Trojan, Tunnel, Tun,
    Tuic, Hysteria2, Anytls, Mieru, Sudoku,
    TrustTunnel, ShadowQuic,
    Inner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode { Normal, Mapping, FakeIp }

/// 目标地址：域名或 IP 二选一，与 Go 的 Host/DstIP 组合等价，
/// 但把"既有域名又有 IP"这种非法状态从类型上排除。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dest {
    Domain { host: Box<str>, port: u16 },
    Ip { ip: IpAddr, port: u16 },
}

#[derive(Debug, Clone)]
pub struct Metadata {
    pub network: Network,
    pub conn_type: ConnType,
    pub src: SocketAddr,
    pub dest: Dest,
    pub in_ip: IpAddr,
    pub in_port: u16,
    pub in_name: Box<str>,
    pub in_user: Option<Box<str>>,
    pub dns_mode: DnsMode,
    pub host: Option<Box<str>>,      // 规则判定用的域名（可能是 sniff 出来的）
    pub process: Option<Box<str>>,
    pub process_path: Option<Box<str>>,
    pub uid: Option<u32>,
    pub special_proxy: Option<Box<str>>,
    pub special_rules: Option<Box<str>>,
    pub dscp: u8,
    pub sniff_host: Option<Box<str>>,
    pub remote_dst: Option<Box<str>>,
    /// 只有 TUN / redir 入站才有的原始包字节，用于首包嗅探。
    pub raw_payload: Option<Bytes>,
}
```

与 Go 的 `Metadata` 对照时注意三点：

1. Go 的 `Host` 与 `DstIP` 可以同时有值，且 `DNSMode` 决定谁优先。Rust 用 `Dest` + `host` 表达同样的信息，但**必须提供一个 `rule_host()`**，语义与 Go 的 `Metadata.RuleHost()` 完全一致（host 优先，其次 IP 字符串），否则 36 条规则的匹配面会悄悄改变。
2. `RawSrcAddr/RawDstAddr` 不搬。Go 用它做 `process` 查找和日志；Rust 用 `src` + `in_ip/in_port` 足够，进程查找单独走平台模块。
3. `Clone` 必须便宜（都是 `Arc`/`Box<str>`），因为 UDP 路径上 `preHandleMetadata(metadata.Clone())` 是热路径。

## 3. 出站：`Proxy` trait

```rust
// crates/skyward-core/src/model/proxy.rs
use async_trait::async_trait;

pub type AdapterName = Box<str>;

pub struct ProxyInfo {
    pub name: AdapterName,
    pub kind: ProxyKind,          // 对应 Go 的 AdapterType，仅用于展示/API
    pub addr: String,
    pub udp: bool,
    pub xudp: bool,
    pub tfo: bool,
    pub mptcp: bool,
    pub smux: bool,
    pub iface: Option<Box<str>>,
    pub routing_mark: u32,
    pub provider_name: Option<Box<str>>,
    pub dialer_proxy: Option<Box<str>>,
}

/// 一次拨号的上下文。Go 里这些是 context.Context 里塞的值 + 全局变量，
/// Rust 里显式化，便于测试与并发推理。
pub struct DialCtx<'a> {
    pub metadata: Metadata,
    pub chains: Vec<AdapterName>,      // 参考 Go 的 Connection.AppendToChains
    pub provider_chains: Vec<AdapterName>,
    pub deadline: Option<Instant>,
    pub dialer: Option<&'a dyn Dialer>, // 供 dialer-proxy 递归
    pub loop_guard: LoopGuard,          // 检测 dialer-proxy 环
}

#[async_trait]
pub trait Proxy: Send + Sync + 'static {
    fn info(&self) -> &ProxyInfo;

    /// 建立 TCP-ish 连接。返回的 `Conn` 必须已经完成协议握手，
    /// 且 `RemoteDestination()` 可用（用于统计与 API）。
    async fn connect(&self, cx: DialCtx<'_>) -> Result<Conn, Error>;

    /// 建立 UDP 会话。不支持时返回 `Error::NotSupported`。
    async fn listen_packet(&self, cx: DialCtx<'_>) -> Result<PacketConn, Error> {
        Err(Error::NotSupported)
    }

    fn support_udp(&self) -> bool { self.info().udp }
    fn support_uot(&self) -> bool { false }
    /// L3 协议（wireguard/tun）返回 true，DNS 模块据此跳过域名解析。
    fn is_l3(&self) -> bool { false }

    /// 组类出站把自己展开成当前成员；叶子返回 None。
    fn unwrap(&self, m: &Metadata) -> Option<Arc<dyn Proxy>> { None }

    /// 关闭资源（如长连接池、QUIC endpoint）。默认空实现。
    fn close(&self) -> Result<(), Error> { Ok(()) }
}
```

**为什么 `DialCtx` 里带 `metadata` 而不是 `&Metadata`**：Go 版本里 `metadata.RemoteDst`、`metadata.Host` 会在拨号过程中被写回（例如 VMess 的 `alterId` 改目标、`remoteDst` 记录真实出口）。用 `&mut Metadata` 也能做，但 `async fn` 里跨 await 持可变借用会逼疯借用检查器；按值传入、按需返回更干净。

**组（Selector / UrlTest / Fallback / LoadBalance / Relay）** 共享一套 `GroupBase`：

```rust
pub struct GroupBase {
    info: ProxyInfo,
    members: ArcSwap<Vec<Arc<dyn Proxy>>>,   // provider 更新时整体替换
    selection: ArcSwap<Option<AdapterName>>,
    filter: Option<Regex>,
    exclude_filter: Option<Regex>,
    exclude_types: SmallVec<[ProxyKind; 4]>,
    failed: AtomicU32,
    test_url: Option<Box<str>>,
    // 健康检查句柄
    health: Mutex<Option<HealthCheckHandle>>,
}
```

选择策略只实现一个函数：

```rust
pub trait GroupStrategy: Send + Sync {
    fn pick<'a>(&self, members: &'a [Arc<dyn Proxy>], sel: &Selection) -> Option<&'a Arc<dyn Proxy>>;
}
```

## 4. 规则

```rust
// crates/skyward-rules/src/lib.rs
pub enum MatchResult { NoMatch, Hit { adapter: AdapterName } }

pub struct MatchHelper<'a> {
    /// 惰性解析：只有 IP 类规则会调用；`no-resolve` 时置 None。
    pub resolve_ip: Option<&'a mut dyn FnMut()>,
    pub find_process: Option<&'a mut dyn FnMut()>,
    pub check_pass_rule: Option<&'a dyn Fn(&str) -> bool>,
}

pub trait Rule: Send + Sync {
    fn kind(&self) -> RuleKind;
    fn matches(&self, m: &Metadata, h: &mut MatchHelper<'_>) -> MatchResult;
    fn adapter(&self) -> &str;
    fn payload(&self) -> Cow<'_, str>;
    fn provider_names(&self) -> SmallVec<[&str; 1]> { SmallVec::new() }
}
```

36 种规则按"看哪个字段"分四组，各自的实现模板固定（逐条对照表见 [appendix/A-rule-types.md](appendix/A-rule-types.md)）：

| 组 | 规则 | 匹配字段 |
| --- | --- | --- |
| 域名 | DOMAIN / SUFFIX / KEYWORD / REGEX / WILDCARD / GEOSITE / REMATCH-NAME | `rule_host()` |
| IP | IP-CIDR / IP-SUFFIX / GEOIP / IP-ASN / SRC-* 变体 | `dest.ip()` 或 `src.ip()`（src 规则交换取值） |
| 端口/协议/入站 | SRC-PORT / DST-PORT / IN-PORT / IN-TYPE / IN-USER / IN-NAME / NETWORK / DSCP / UID | 直接字段 |
| 进程 | PROCESS-NAME / PATH / REGEX / WILDCARD（×2） | 惰性 `find_process()` |
| 复合 | AND / OR / NOT / SUB-RULE / MATCH / RULE-SET | 组合或 provider |

`RuleKind` 是与 API 兼容的字符串（`"DomainSuffix"` 等），`Display` 必须与 Go 的 `RuleType.String()` 逐字一致，因为 `/rules` 返回它。

## 5. 隧道

```rust
// crates/skyward-core/src/tunnel.rs
pub struct Tunnel {
    snapshot: ArcSwap<Snapshot>,
    nat: NatTable,
    stats: Arc<Stats>,
    mode: AtomicCell<Mode>,          // rule / global / direct
    log_level: AtomicU8,
}

pub struct Snapshot {
    pub rules: RuleSet,                 // 已编译的规则树
    pub sub_rules: HashMap<String, RuleSet>,
    pub proxies: HashMap<AdapterName, Arc<dyn Proxy>>,
    pub groups: HashMap<AdapterName, Arc<dyn Proxy>>,
    pub proxy_providers: HashMap<String, Arc<dyn ProxyProvider>>,
    pub rule_providers: HashMap<String, Arc<dyn RuleProvider>>,
    pub dns: Option<Arc<DnsService>>,
    pub general: Arc<GeneralConfig>,
    pub version: u64,                   // 单调递增，供 AllProxies 缓存判定
}
```

核心入口只有三个方法，签名刻意保留 Go 的形状（阻塞式 `handle` 由调用方 `spawn`）：

```rust
impl Tunnel {
    pub fn handle_tcp(&self, conn: Box<dyn AsyncStream>, m: Metadata) -> impl Future<Output = ()>;
    pub fn handle_udp(&self, pkt: Box<dyn UdpPacket>, m: Metadata);
    pub fn nat_table(&self) -> &NatTable;
}
```

`handle_udp` 是**同步、非阻塞**的（Go 注释：`HandleUDPPacket will handle a udp packet nonblocking`）。它只做哈希分片 + `try_send`，满了就 `drop`。

## 6. 入站

```rust
#[async_trait]
pub trait Inbound: Send + Sync {
    fn name(&self) -> &str;
    fn address(&self) -> String;
    fn raw_address(&self) -> &str;
    async fn listen(self: Arc<Self>, tunnel: Arc<Tunnel>) -> Result<(), Error>;
    async fn close(&self);
    /// 用于 API 的 `/configs`：判断配置是否变化以决定是否重建。
    fn config_eq(&self, other: &dyn Any) -> bool;
}
```

入站与隧道之间只通过 `Tunnel` 交互，不认识具体协议。这与 Go 的 `InboundListener.Listen(tunnel C.Tunnel)` 等价。

## 7. Provider

```rust
#[async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &str;
    fn vehicle_type(&self) -> VehicleType;
    async fn initial(&self) -> Result<(), Error>;
    async fn update(&self) -> Result<(), Error>;
}

#[async_trait]
pub trait ProxyProvider: Provider {
    fn proxies(&self) -> Arc<Vec<Arc<dyn Proxy>>>;
    fn count(&self) -> usize;
    fn touch(&self);                       // 用于"按需健康检查"
    fn version(&self) -> u32;
    async fn health_check(&self);
    fn subscription_info(&self) -> Option<&SubscriptionInfo>;
}

#[async_trait]
pub trait RuleProvider: Provider {
    fn behavior(&self) -> RuleBehavior;    // Domain / IpCidr / Classical
    fn count(&self) -> usize;
    fn matches(&self, m: &Metadata, h: &mut MatchHelper<'_>) -> bool;
    fn strategy(&self) -> &dyn Any;
}
```

`Vehicle` 与 Go 一致（File / Http / Compatible / Inline），但 Rust 里用 `enum Vehicle` 而不是 trait，因为只有四种而且都能静态派发：

```rust
pub enum Vehicle {
    File { path: PathBuf },
    Http { url: Url, proxy: Option<AdapterName>, headers: HeaderMap, etag: Option<ETag> },
    Inline { payload: Bytes },
    Compatible { url: Url, proxy: Option<AdapterName> },  // 订阅链接自动转 Clash 配置
}
```

## 8. 错误模型

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not supported")]                    NotSupported,
    #[error("rejected by rule")]                 Rejected,
    #[error("timeout: {0}")]                     Timeout(&'static str),
    #[error("dns: {0}")]                         Dns(#[from] DnsError),
    #[error("io: {0}")]                          Io(#[from] std::io::Error),
    #[error("protocol {proto}: {message}")]      Protocol { proto: &'static str, message: String },
    #[error("auth failed")]                      Auth,
    #[error("dialer-proxy loop at {0}")]         DialerLoop(AdapterName),
    #[error("configuration: {0}")]               Config(String),
}
```

要点：

- `Error` 可 `Clone` 不现实（含 `io::Error`），但必须能映射成 API 的 `{"message": "..."}`。
- `Error::Rejected` 与 `Error::NotSupported` 要能和 Go 的行为对齐：`REJECT` 规则命中时不拨号、直接关闭；UDP 不支持时**跳过该条规则继续匹配**（见 00 §3）。
- 协议 crate 内部用 `Result<T, Error>`，不抛 panic；解析外部字节（VMess 头、SOCKS 请求）必须走 `Result`，因为这是安全边界。

## 9. 钩子（宿主可见的行为）

Go 版用包级变量做回调。Rust 版集中成两个结构体，一处注册：

```rust
#[derive(Default, Clone)]
pub struct Hooks {
    pub on_provider_loaded: Option<Arc<dyn Fn(&str) + Send + Sync>>,
    pub on_dns_query:       Option<Arc<dyn Fn(&DnsQueryRecord) + Send + Sync>>,
    pub on_connection:      Option<Arc<dyn Fn(&ConnEvent) + Send + Sync>>,
    pub on_geo_update:      Option<Arc<dyn Fn(GeoUpdate) + Send + Sync>>,
    pub on_url_test:        Option<Arc<dyn Fn(&UrlTestResult) + Send + Sync>>,
    pub on_dialer_loop:     Option<Arc<dyn Fn(&str) + Send + Sync>>,
    pub on_proxy_switch:    Option<Arc<dyn Fn(&str, &str) + Send + Sync>>,
}
```

这些就是 Go 里 `DefaultProviderLoadedHook`、`DefaultQueryNotify`、`DefaultRequestNotify`、`GeoUpdateHook`、`UrlTestHook`、`DefaultLoopNotify`、`SwitchProxiesCallback` 的对应物。**一个都不能漏**，否则应用侧会静默失去功能（比如 DNS 面板不再刷新、订阅加载进度不再显示）。
