# 06 · 配置与 DNS

## 1. 配置的两段式

Go 版把配置解析分成两段，这个设计非常好，Rust 版照抄：

```
raw YAML (map[string]any)
   └─ UnmarshalRawConfig  → RawConfig        （宽容解析、默认值、类型转换）
        └─ ParseRawConfig  → Config          （构造对象：出站、规则、DNS、provider…）
             └─ executor.ApplyConfig → 全局状态（Go） / Tunnel::apply(Snapshot)（Rust）
```

为什么要分：`RawConfig` 是可以**直接回写给 API** 的（`PATCH /configs` 改一项），而 `Config` 是活的、带连接池的、不能序列化的对象。

Rust 版：

```rust
// crates/skyward-config/src/lib.rs
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct RawConfig {
    pub port: u16,
    pub socks_port: u16,
    pub redir_port: u16,
    pub tproxy_port: u16,
    pub mixed_port: u16,
    pub allow_lan: bool,
    pub bind_address: String,
    pub mode: Mode,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub authentication: Vec<String>,
    pub skip_auth_prefixes: Vec<IpNet>,
    pub lan_allowed_ips: Vec<IpNet>,
    pub lan_disallowed_ips: Vec<IpNet>,
    pub external_controller: String,
    pub external_controller_tls: String,
    pub external_controller_unix: String,
    pub external_controller_pipe: String,
    pub secret: String,
    pub external_ui: String,
    pub unified_delay: bool,
    pub interface_name: String,
    pub routing_mark: u32,
    pub tcp_concurrent: bool,
    pub find_process_mode: FindProcessMode,
    pub global_ua: String,
    pub etag_support: bool,
    // ... 约 90 个顶层字段，见 config/config.go RawConfig
    pub proxies: Vec<serde_yaml::Value>,        // 故意保留为 Value，见下
    pub proxy_groups: Vec<serde_yaml::Value>,
    pub proxy_providers: IndexMap<String, serde_yaml::Value>,
    pub rules: Vec<String>,
    pub sub_rules: IndexMap<String, Vec<String>>,
    pub rule_providers: IndexMap<String, serde_yaml::Value>,
    pub listeners: Vec<serde_yaml::Value>,
    pub hosts: IndexMap<String, serde_yaml::Value>,
    pub dns: RawDns,
    pub tun: RawTun,
    pub sniffer: RawSniffer,
    pub profile: RawProfile,
    pub experimental: RawExperimental,
    pub geox_url: RawGeoxUrl,
    pub ntp: RawNtp,
    pub iptables: RawIptables,
    pub tls: RawTls,
    pub tunnels: Vec<TunnelConfig>,
}
```

### 为什么 `proxies`/`listeners` 是 `serde_yaml::Value`

Go 版用 `map[string]any` + 自定义 `structure` 解码器（`WeaklyTypedInput`）来容忍：

- `port: "443"`（字符串当数字）
- `udp: "true"`（字符串当布尔）
- `snell` 的 `psk` 既可以是字符串也可以是数组
- 同一个字段的多种别名（`servername` / `sni` / `server-name`）

`serde` 默认会拒绝这些。所以 Rust 版需要一层**宽容解码**：

```rust
// crates/skyward-config/src/lenient.rs
pub trait Lenient {
    fn as_bool(&self) -> Option<bool>;   // true/false/"true"/1/1.0
    fn as_u16(&self) -> Option<u16>;
    fn as_string(&self) -> Option<String>; // 数字/布尔也转字符串
    fn get_alias(&self, keys: &[&str]) -> Option<&Value>; // 按顺序找第一个存在的键
}

pub fn decode_proxy(v: &serde_yaml::Value) -> Result<ProxyConfig, ConfigError> {
    let kind = v.get_str("type")?;
    let name = v.get_str("name")?;
    let server = v.get_alias(&["server", "host"])?;
    // 每个协议一个 decode_<kind>()，用宏减少样板
    protocols::decode(kind, v)
}
```

**测试**：把 `docs/config.yaml`（144 KB，仓库里的官方示例）作为一份"必须能解析"的 fixture，逐字段断言。这是最省力的兼容性测试。

## 2. 默认值

Go 的 `DefaultRawConfig()` 定义了全部默认值。Rust 用 `Default` 实现 + `#[serde(default)]`，但有几个**非直觉**的默认必须在文档里写死，否则行为会变：

| 字段 | 默认 | 出处 |
| --- | --- | --- |
| `bind-address` | `"*"` | `DefaultRawConfig` |
| `lan-allowed-ips` | `["0.0.0.0/0", "::/0"]` | 同上 |
| `mode` | `rule` | 同上 |
| `log-level` | `info` | 同上 |
| `ipv6` | `true` | 同上 |
| `geo-update-interval` | `24`（小时） | 同上 |
| `geodata-loader` | `"memconservative"` | 同上 |
| `global-ua` | `"clash.meta/" + Version` | 同上 |
| `etag-support` | `true` | 同上 |
| `find-process-mode` | `strict` | 同上 |
| `dns.fake-ip-range` | `198.18.0.1/16` | 同上 |
| `dns.fake-ip-ttl` | `1` | 同上 |
| `dns.ipv6` | `false`（注意与顶层 `ipv6: true` 不同） | 同上 |
| `dns.default-nameserver` | `114.114.114.114, 223.5.5.5, 8.8.8.8, 1.0.0.1` | 同上 |
| `dns.nameserver` | `https://doh.pub/dns-query, tls://223.5.5.5:853` | 同上 |
| `dns.enhanced-mode` | `mapping` | 同上 |
| `tun.stack` | `mips` | `inbound.TunOption` 的默认 |
| `tun.dns-hijack` | `["0.0.0.0:53"]` | 同上 |
| `DefaultTCPTimeout` | `5s` | `component/dialer` |
| `DefaultDropTime` | `60s`（`12 × 5s`） | `constant/adapters.go` |
| `udp` 会话超时 | `60s` | `tunnel/tunnel.go` |
| `health-check` 默认 URL | `https://www.gstatic.com/generate_204` | `constant/adapters.go` |

> 提示：`dns.ipv6` 默认为 `false` 而顶层 `ipv6` 默认 `true` 是历史原因。Rust 版**照抄**，在注释里说明这是兼容性而非设计。

## 3. 生效与热更新

`PATCH /configs` 支持部分更新（指针字段 = "没提供"）：

```rust
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigPatch {
    pub port: Option<u16>,
    pub socks_port: Option<u16>,
    pub mode: Option<Mode>,
    pub log_level: Option<LogLevel>,
    pub allow_lan: Option<bool>,
    #[serde(flatten)]
    pub dns: Option<RawDns>,
    // ...
}
```

流程（与 Go 的 `executor.ApplyConfig` 对齐）：

```
PATCH 请求
  ├─ 记录各模块是否需要重建：dns_changed / proxies_changed / rules_changed / general_changed
  ├─ 构造新 Snapshot（失败则整体回滚，返回 400 + 具体错误）
  ├─ tunnel.apply(new_snapshot)
  ├─ listener_manager.reconcile(new_general)   // 端口/认证/allow-lan
  └─ api.rebind_if_needed(new_controller)
```

**顺序很重要**：先 `tunnel.apply` 再 reconcile 监听器。反过来的话，新端口会短暂地在旧规则下放行流量。

## 4. 配置里的"运行时对象"

有三类字段会绑定到活对象，不能只做 `Clone`：

| 字段 | 绑定 | 更新方式 |
| --- | --- | --- |
| `proxies[].dialer-proxy` | 指向另一个 proxy 的引用 | 按名字在 Snapshot 内解析，循环检测在拨号时做 |
| `proxy-groups[].proxies` | 成员列表（可能来自 provider） | provider 更新时 `ArcSwap` 替换 `GroupBase.members` |
| `tls.certificate` / `private-key` | 证书与私钥（可能是路径，也可能是内联 PEM） | `ArcSwap<Arc<CertifiedKey>>`，热更新时重载 |
| `custom-certifactes` | 额外信任的根 | 重新构造 `rustls::RootCertStore` |
| `authentication` | 用户表 | `ArcSwap<AuthStore>` |

## 5. DNS

### 5.1 结构

Go 的 `dns` 包分得很清楚，Rust 照此拆：

```
server      ← 监听 UDP/TCP 53，解报文，调 handler        （dns/server.go）
service     ← 报文 ↔ Resolver 的收敛点，补 EDNS0          （dns/service.go）
handler     ← 中间件链                                   （dns/middleware.go）
resolver    ← 选上游 + 并发查询 + 缓存                    （dns/resolver.go）
client      ← udp / tcp / tls / https / quic / dhcp / rcode（dns/{client,doh,dot,doq}.go）
enhancer    ← fake-ip / mapping 池                       （dns/enhancer.go）
policy      ← nameserver-policy 路由                     （dns/policy.go）
```

### 5.2 上游协议

配置字符串的解析在 `config/config.go::parseNameServer`（`udp://` 可省略、`#proxy-name` 片段表示走代理、`&name-server=...` 表示引导解析）。支持的 scheme：

| scheme | 默认端口 | 实现 |
| --- | --- | --- |
| `udp`（无 scheme 亦同） | 53 | tokio UDP |
| `tcp` | 53 | 2 字节长度前缀 |
| `tls` | 853 | rustls + 长度前缀 |
| `https` / `http` | 443 / 80 | hyper + `application/dns-message`（GET base64url / POST） |
| `quic` | 853 | quinn（DoQ，RFC 9250，每条查询一个 stream） |
| `h3` | 443 | DoH over HTTP/3（`prefer-h3` 开关） |
| `system` | — | 平台 resolver |
| `dhcp` | — | 从 DHCP 租约取（仅 Android/Linux 有意义） |
| `rcode` | — | 固定应答（用于广告拦截的 **fake 应答**，如 `rcode://success` / `refused`） |
| `ts` / `et` | — | Tailscale / EasyTier 内部 DNS（挂起） |

报文编解码用 `hickory-proto`（原 trust-dns-proto），它能构建/解析完整的 `Message`，并支持 EDNS0。**不建议手写** DNS 解析——它会把你拖进压缩指针、OPT、DNSSEC 的泥潭。

### 5.3 中间件链

```rust
type Handler = Arc<dyn Fn(Arc<DnsQuery>, Next) -> BoxFuture<'static, Arc<DnsResponse>> + Send + Sync>;

// 顺序必须与 Go 的 newHandler 一致：
//   hosts? -> fake-ip? -> mapping? -> resolver
```

Go 的 `newHandler` 顺序：

```go
if mapper.useHosts      { add withHosts }
if mode == fake-ip      { add withFakeIP }
if mode != normal       { add withMapping }
return compose(..., withResolver)
```

Rust 版用 `tower::Service` 或手写 boxed future 都可以；关键是**顺序与短路**。`withHosts` 命中就直接返回（还要带 CNAME），`withFakeIP` 对 A/AAAA 返回 fake 地址并写入池，`withMapping` 在应答后建立 IP↔域名映射。

### 5.4 fake-ip

Go 的 `component/fakeip`：

- `198.18.0.0/15` 段内分配（默认 `198.18.0.1/16`）
- 网关地址保留，广播地址保留
- `fake-ip-filter` 里的域名不分配（按 `*.` / `+.` / 正则）
- 池持久化到缓存（`store-fake-ip`）
- TTL 默认 1 秒（防止客户端长期缓存）

Rust 版实现要点：

```rust
pub struct FakeIpPool {
    range: IpNet,
    next: AtomicU32,                       // 环形分配
    by_host: DashMap<Box<str>, IpAddr>,
    by_ip: DashMap<IpAddr, Box<str>>,
    skipped: DomainSet,                    // fake-ip-filter
}
```

**注意**：`next` 必须是环形且跳过多播/环回；Go 的实现里 `cycle` 标志决定是否回绕。Rust 版同样保留"用尽即回绕"的行为，不要报错。

### 5.5 DNS 劫持（TUN）

TUN 栈收到目标端口 53 的包时：

1. 若目标命中 `dns-hijack` 列表 → 交给 `skyward-dns` 的服务实例处理；
2. 否则按普通 UDP 流走规则（可能被 `dns-out` 出站接走，这是 Clash 的经典写法）。

`Dns` 出站（`adapter/outbound/dns.go`）就是"把这个连接的目标交给本地 DNS 解析并返回一个假连接"，Rust 版照实现。

### 5.6 缓存与 TTL

- 正向缓存：key = `(qname, qtype, qclass)`，value = 响应 + 过期时间。
- 遵循响应里的最小 TTL，且不低于配置下限。
- `POST /cache/dns/flush` 清空；`POST /cache/fakeip/flush` 只清 fake-ip 池。
- 查询超时 `DefaultDNSTimeout`（Go 为 5s），并发查询时"先答先用"（`dns/resolver.go` 的并发策略），但要保留 `fallback-lazy-query` 的语义。

## 6. hosts

Go 的 `component/trie` 用 `DomainTrie<HostValue>` 支持：

```yaml
hosts:
  "example.com": 1.2.3.4
  "*.example.com": 5.6.7.8
  "multi.example.com": [1.1.1.1, 2.2.2.2]
  "cname.example.com": other.host
```

Rust 版用 `DomainTrie<HostValue>` 等价物（自己写，约 200 行，因为要支持 `*.` 与 `+.` 通配与"取剩余段"语义）。

`useHosts` 与 `useSystemHosts` 两个开关都要保留：前者查 Clash 的 `hosts:`，后者查系统 `/etc/hosts`。

## 7. NTP

`ntp/ntp` 提供时间源，用于 TLS 证书校验（`tls.Config{Time: ntp.Now}`）与 DNS TTL。Rust 版：

- 用一个 `Arc<TimeSource>`，内部 `AtomicI64` 存"服务器时间 - 本地单调时钟"偏移。
- 默认不启用（`ntp.enable: false`），启用时按 `interval` 拨号更新，`write-to-system` 需 root，默认 false。
- **所有 TLS 握手都要读这个源**，否则在系统时间错误的设备上会全线握手失败——这是 Go 版存在此模块的原因。
