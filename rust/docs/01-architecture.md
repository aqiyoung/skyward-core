# 01 · 架构总览

## 1. 设计原则

1. **依赖只朝一个方向**：`core` 不依赖任何具体协议；协议 crate 只依赖 `core`。`app`（二进制/FFI）是唯一把所有东西拼起来的地方。
2. **策略用 trait，机制用具体类型**。`Proxy`、`Rule`、`Inbound`、`Provider` 是 trait；`Metadata`、`Snapshot`、`Selector` 是具体类型。Go 版 37 个 `AdapterType` 常量不翻译成 trait，而是做成 `ProxyKind` 枚举用于展示/API。
3. **热重载靠 `ArcSwap` 快照**，不用 `RwLock<HashMap>`。读路径无锁，写路径整体替换。
4. **每条连接一个 task，不共享 future**。连接级状态放在任务局部变量里，跨任务共享的只有 `Arc` 与 channel。
5. **错误的边界是协议层**。`Error` 是枚举（可判等、可分类），不随随便便装箱 `anyhow::Error`；只有入口（CLI、API handler）才收敛成人类可读信息。
6. **可测量的门禁**：每个里程碑都要跑规则对拍与基准（[10-parity-benchmark.md](10-parity-benchmark.md)），不靠"看起来对"。

## 2. crate 划分

```
skyward-core/                  # workspace 根（rust/Cargo.toml）
├── crates/
│   ├── skyward-core/          # 内核本体：tunnel、metadata、snapshot、规则调度
│   ├── skyward-rules/         # 36 种规则 + ruleset（MRS）读写 + trie/set
│   ├── skyward-config/        # Clash YAML 配置：RawConfig → Config，热更新
│   ├── skyward-dns/           # resolver、上游协议、fake-ip、策略、中间件链
│   ├── skyward-proxy/         # 出站协议实现（按 feature 裁剪）
│   ├── skyward-transport/     # 传输层复用：TLS/uTLS、WS、gRPC、HTTP、smux、QUIC 适配
│   ├── skyward-inbound/       # http/socks/mixed/tun/redir/tproxy/ss/trojan/vmess...
│   ├── skyward-api/           # 外部控制器：axum 路由、WebSocket 流、DoH 入口
│   ├── skyward-provider/      # proxy-provider / rule-provider、健康检查、订阅信息
│   ├── skyward-ffi/           # cdylib：C ABI / JNI 表面
│   └── skywardd/              # CLI 二进制：读配置、跑起来、调试用
└── xtask/                     # 对拍与基准的编排（cargo xtask）
```

依赖方向（箭头表示"依赖"）：

```
skywardd ──► skyward-ffi ──► skyward-api ──┐
    │                          │           │
    └──────────► skyward-config┴──► skyward-core ◄── skyward-rules
                                     ▲   ▲   ▲
                        skyward-proxy│   │   │skyward-inbound
                                     │   │   │
                              skyward-transport┘
                                     ▲
                              skyward-dns（被 core 与 proxy 引用，但不反向依赖）
                                     ▲
                             skyward-provider（引用 core+rules+dns）
```

硬规则：

- `skyward-core` **不得** 依赖 `skyward-proxy` / `skyward-inbound` / `skyward-api`。
- `skyward-rules` 不得依赖 `skyward-dns`（规则只知道 `Metadata` 和惰性 `ResolveIp` 回调）。
- `skyward-transport` 不得依赖任何具体协议 crate。
- 只有 `skyward-ffi`、`skywardd`、`skyward-api` 允许出现 `anyhow`。

## 3. Cargo workspace

下面是起始骨架的 `rust/Cargo.toml`（M0 落地时照此创建）。版本号与 feature 集会在 M0 按实际可用的依赖再收紧一次：这里列的是**设计与选型结论**，不是此刻已经验证过的锁定版本。

```toml
[workspace]
resolver = "2"
members = [
  "crates/skyward-core",
  "crates/skyward-rules",
  "crates/skyward-config",
  "crates/skyward-dns",
  "crates/skyward-transport",
  "crates/skyward-proxy",
  "crates/skyward-inbound",
  "crates/skyward-provider",
  "crates/skyward-api",
  "crates/skyward-ffi",
  "crates/skywardd",
  "xtask",
]

[workspace.package]
edition = "2021"
rust-version = "1.75"
license = "GPL-3.0-only"
repository = "https://github.com/aqiyoung/skyward-core"

[workspace.dependencies]
# 运行时
tokio = { version = "1", features = ["rt-multi-thread", "net", "io-util", "sync", "time", "macros", "signal"] }
futures = "0.3"
pin-project-lite = "0.2"
tower = "0.5"
tower-http = { version = "0.6", features = ["cors", "fs", "trace"] }

# 数据与并发
arc-swap = "1"
parking_lot = "0.12"
dashmap = "6"
indexmap = { version = "2", features = ["serde"] }
bytes = "1"
bytemuck = "1"
crossbeam-queue = "0.3"
rand = "0.8"
smallvec = "1"

# 序列化
serde = { version = "1", features = ["derive"] }
serde_yaml_ng = "0.10"          # YAML 1.1/1.2 宽容解析；键序保留靠 indexmap
serde_json = "1"

# HTTP / TLS
hyper = { version = "1", features = ["http1", "http2", "server", "client"] }
hyper-util = { version = "0.1", features = ["tokio", "server", "client-legacy"] }
http = "1"
http-body-util = "0.1"
axum = { version = "0.8", features = ["ws"] }
rustls = { version = "0.23", default-features = false, features = ["ring", "tls12", "std"] }
tokio-rustls = "0.26"
webpki-roots = "0.26"
rustls-pemfile = "2"
tokio-tungstenite = { version = "0.24", features = ["rustls-tls-webpki-roots"] }
h2 = "0.4"
hickory-proto = "0.24"          # DNS 报文编解码（替代 miekg/dns）
hickory-resolver = "0.24"

# 协议与密码学
aes = "0.8"
aes-gcm = "0.10"
chacha20poly1305 = "0.10"
sha1 = "0.10"
sha2 = "0.10"
hmac = "0.12"
hkdf = "0.12"
md-5 = "0.10"
blake3 = "1"
ed25519-dalek = "2"
x25519-dalek = "2"
uuid = { version = "1", features = ["v4"] }
quinn = "0.11"                  # QUIC（TUIC/Hysteria2/MASQUE）
rustls-quinn = "0.1"
async-trait = "0.1"
httparse = "1"
base64 = "0.22"
flate2 = "1"
zstd = "0.13"
regex = "1"
ipnet = "2"
maxminddb = "0.24"

# 可观测
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# 平台
libc = "0.2"
socket2 = { version = "0.5", features = ["all"] }
nix = { version = "0.29", features = ["net", "sched", "user"] }
windows-sys = { version = "0.59", features = ["WinSock2", "WinBase"] }

# 内部
skyward-core = { path = "crates/skyward-core" }
skyward-rules = { path = "crates/skyward-rules" }
skyward-config = { path = "crates/skyward-config" }
skyward-dns = { path = "crates/skyward-dns" }
skyward-transport = { path = "crates/skyward-transport" }
skyward-proxy = { path = "crates/skyward-proxy" }
skyward-inbound = { path = "crates/skyward-inbound" }
skyward-provider = { path = "crates/skyward-provider" }
skyward-api = { path = "crates/skyward-api" }
```

`Cargo.toml` 里的 feature 设计（`skyward-proxy` 为例）：

```toml
[features]
default = ["protocol-basic"]
protocol-basic = ["ss", "trojan", "socks5", "http"]
ss       = ["dep:aes-gcm", "dep:chacha20poly1305", "dep:hkdf"]
trojan   = ["skyward-transport/tls"]
vmess    = ["skyward-transport/ws", "skyward-transport/grpc"]
vless    = ["vmess", "skyward-transport/reality"]
tuic     = ["skyward-transport/quic"]
hysteria2= ["skyward-transport/quic"]
wireguard= ["dep:boringtun"]
tun      = ["skyward-inbound/tun"]
full     = ["ss","trojan","vmess","vless","tuic","hysteria2","socks5","http"]
```

这与 Go 版的 build tag 一一对应（`with_gvisor`、`no_tailscale`、`no_zerotier`、`no_easytier`、`no_fake_tcp`、`with_low_memory`），但粒度更细：**裁剪单位是协议，不是"整套 mesh VPN"**。应用侧原来只能整体开关 easytier/tailscale/zerotier，Rust 版可以按需装 `ss + vmess + trojan` 得到 2–3 MB 的库。

## 4. 进程与任务拓扑

```
                       ┌─────────────────────────────┐
   FFI/CLI ──start──►  │ App (skyward-ffi/skywardd)  │
                       │  ├─ Config 加载与热更新      │
                       │  ├─ API server (axum)       │
                       │  └─ 启停 inbounds           │
                       └──────────┬──────────────────┘
                                  │ Arc<ArcSwap<Snapshot>>
                       ┌──────────▼──────────────────┐
                       │ Tunnel                      │
                       │  ├─ rule engine (读快照)     │
                       │  ├─ proxy table (读快照)     │
                       │  ├─ nat 表 (跨快照的生命)     │
                       │  └─ statistics manager      │
                       └──────────┬──────────────────┘
             ┌────────────────────┼────────────────────┐
      inbound accept task   udp dispatch task     dns service
             │                    │                    │
      per-conn task ──────────────┴────────────► per-proxy tasks
```

任务纪律：

- **accept task** 只做 accept + `Metadata` 构造 + `spawn`，不做 DNS、不做规则匹配。
- **per-conn task** 负责该连接的一切：嗅探、规则、拨号、relay。它被取消即连接关闭，不需要额外的注册表。
- **UDP dispatch** 是 N 个（默认 = CPU 核数，最小 4）固定 task，按 key 哈希分片，队列 `try_send`。
- **API server** 与隧道共享同一个 tokio runtime，但用独立 task 组，重启时只影响它自己。

## 5. 与 Go 版的目录对照

| Go 包 | Rust crate / 模块 | 备注 |
| --- | --- | --- |
| `constant/` | `skyward-core::model` | 枚举、`Metadata`、trait 定义 |
| `tunnel/` + `tunnel/statistic` | `skyward-core::tunnel`、`::stat` | 快照、调度、NAT、统计 |
| `rules/` | `skyward-rules` | 逐规则一文件，与 Go 同构 |
| `adapter/` | `skyward-proxy` + `skyward-provider` | 出站与组、订阅 |
| `listener/` | `skyward-inbound` | 含 `tun` 子模块 |
| `transport/` | `skyward-transport` + `skyward-proxy::*` | 线与协议分离 |
| `dns/` | `skyward-dns` | |
| `config/` | `skyward-config` | |
| `hub/` | `skyward-api`（route）+ `skyward-core::exec`（executor） | |
| `common/` | 大部分删除，`BufConn`/`CachedConn`/`EarlyConn` 进 `skyward-core::io` | 见 00 §3 |
| `log/` | `tracing` + `skyward-core::log` 适配层 | API 要能订阅日志流 |
| `context/` | 用 `tokio::task_local!` 或显式传参 | Go 的 `context.Context` 语义在 Rust 里不照搬 |
| `main.go` | `skywardd` + `skyward-ffi` | 拆成 CLI 与库两个入口 |
