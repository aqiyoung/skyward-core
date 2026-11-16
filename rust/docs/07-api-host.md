# 07 · API 与宿主接口

## 1. REST API 是兼容性契约

面板（metacubexd 等）不读源码，只读 JSON。所以 `skyward-api` 的验收标准是：**同一份配置，Go 版与 Rust 版的每个响应在字段名、类型、缺省行为上一致**。

Go 版的路由表（`hub/route/*.go`，54 条）：

| 前缀 | 方法 | 路径 | 说明 |
| --- | --- | --- | --- |
| `/` | GET | `/` | `{"hello":"mihomo"}` |
| | GET | `/version` | `{"meta":true,"version":"1.10.0"}` |
| | GET | `/logs` | WebSocket，`{type,payload}` |
| | GET | `/traffic` | WebSocket 或 JSON `{up,down,upTotal,downTotal}` |
| | GET | `/memory` | `{inuse,oslimit}` |
| | GET / PUT / PATCH | `/configs` | 读取 / 全量替换 / 部分更新 |
| | POST | `/configs/geo` | 更新 Geo 数据 |
| | GET | `/proxies` | 全部代理（组也包含） |
| | GET | `/proxies/{name}` | 单个，含 `history` |
| | GET | `/proxies/{name}/delay` | 测速（`?url=&timeout=`） |
| | PUT | `/proxies/{name}` | 切换组内选择 |
| | DELETE | `/proxies/{name}` | 取消固定 |
| | GET | `/group` / `/group/{name}` / `/group/{name}/delay` | 组视图 |
| | GET | `/providers/proxies` … | 订阅 provider |
| | GET / PUT | `/providers/rules/{name}` | 规则 provider |
| | GET | `/rules` | 规则列表（含命中计数） |
| | PATCH | `/rules/disable` | 禁用/启用规则 |
| | GET / DELETE | `/connections` | 快照 / 全关闭 |
| | DELETE | `/connections/{id}` | 关闭单条 |
| | GET | `/connections`（WS） | 实时推送，`?interval=` |
| | GET | `/dns/query` | `?name=&type=` |
| | GET / POST | `/doh`（可配置的 `external-doh-server`） | DoH 入口 |
| | POST | `/cache/fakeip/flush` / `/cache/dns/flush` | |
| | GET / PUT / DELETE | `/storage/{key}` | 面板的键值存储，1 MiB 上限 |
| | POST | `/restart` | 重启进程（embed 模式禁用） |
| | POST | `/upgrade` / `/upgrade/geo` / `/upgrade/ui` | 自更新（embed 模式禁用） |
| | GET | `/ui/*` | 静态面板文件 |
| | `PUT /debug/gc` + pprof | `/debug/*` | 仅 debug 日志级别时挂载 |

### 1.1 认证

`Authorization: Bearer <secret>` 或 `?token=<secret>`，用**常量时间比较**（Go 的 `safeEqual`）。Rust：

```rust
fn safe_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) { diff |= x ^ y; }
    diff == 0
}
```

`external-controller-unix` 的注释明确："从 Unix socket 访问 api 接口不会验证 secret"。Rust 版必须保留这个行为（本地 socket 视为已认证），并在文档里保留同样的警告。

### 1.2 CORS

```yaml
external-controller-cors:
  allow-origins: ["*"]
  allow-private-network: true
```

Rust 用 `tower_http::cors::CorsLayer`，但 `allow-private-network` 对应的 `Access-Control-Allow-Private-Network: true` 需要自己加 header（tower-http 不支持）。

### 1.3 WebSocket 细节

Go 手写握手（`hub/route/common.go::wsUpgrade`），没有用库。Rust 用 `axum::extract::ws`，但要注意三点：

1. `/traffic` 与 `/logs` 的**帧格式**：JSON 文本帧，不是二进制。
2. `/connections` 的 `interval` 查询参数（毫秒，默认 1000）。
3. 客户端断开时 Go 会在写失败后退出循环；Rust 要显式处理 `Close` 帧与写错误，不能让推送任务泄漏。

### 1.4 响应形态

Go 用 `render.JSON` + `render.M`（`map[string]any`），键序不重要但**字段必须存在**。几个容易漏的：

- `/proxies`：未测速过的代理 `history` 是空数组，`alive: true`。
- `/proxies/{name}` 的 `now`（当组的当前选择）在非组上是空字符串。
- `/configs` 返回的是**运行时状态**而不是原始 YAML：端口、tun 配置、dns 部分来自活对象（`hub/executor.GetGeneral`）。
- `/rules` 每条含 `type`、`payload`、`proxy`、`size`、`extra`（hitCount、hitAt、missCount、missAt）。Rust 版的 `RuleKind` 字符串必须逐字匹配（`"DomainSuffix"` 而非 `"domain-suffix"`）。

## 2. DoH 入口

`external-doh-server: /dns-query` 挂载一个 DoH 端点，认证走同一套 secret。它与 DNS 上游的 DoH **不是一回事**：这是"对外提供 DNS 服务"，上游是本地 resolver。

实现要点（对 `hub/route/doh.go`）：

- GET 的 `?dns=` 是 **base64url 无填充**。
- POST 要求 `Content-Type: application/dns-message`，Body 上限 65535。
- 响应 `Content-Type: application/dns-message`，用 POST 时 `Cache-Control: max-age=<最小TTL>`。
- 方法不支持返回 405，DNS 未启用返回 500 + 纯文本 `"DNS section is disabled"`。

## 3. 宿主接口（FFI）

这是 Rust 版**必须一开始就设计对**的部分：应用不是通过 CLI 用内核，而是把它当库。

### 3.1 表面

```rust
// crates/skyward-ffi/src/lib.rs
#[no_mangle]
pub extern "C" fn skyward_create(opts: *const SkywardOptions) -> *mut SkywardHandle;

#[no_mangle]
pub extern "C" fn skyward_apply_config(handle: *mut SkywardHandle, yaml: *const u8, len: usize) -> SkywardStatus;

#[no_mangle]
pub extern "C" fn skyward_start_inbound(handle: *mut SkywardHandle) -> SkywardStatus;

#[no_mangle]
pub extern "C" fn skyward_close_inbound(handle: *mut SkywardHandle);

#[no_mangle]
pub extern "C" fn skyward_test_config(yaml: *const u8, len: usize) -> SkywardStatus;

#[no_mangle]
pub extern "C" fn skyward_query_dns(handle: *mut SkywardHandle, name: *const c_char, qtype: u16, out: *mut DnsAnswer) -> SkywardStatus;

#[no_mangle]
pub extern "C" fn skyward_handle_tun_packet(handle: *mut SkywardHandle, pkt: *const u8, len: usize) -> SkywardStatus;

#[no_mangle]
pub extern "C" fn skyward_set_hooks(handle: *mut SkywardHandle, hooks: *const SkywardHooks);

#[no_mangle]
pub extern "C" fn skyward_destroy(handle: *mut SkywardHandle);
```

设计原则：

1. **句柄是 `Box::into_raw` 的 `Arc<Runtime>` 组合**，所有调用先校验非空。
2. **所有字符串都是 `(ptr, len)`**，不假设 NUL 结尾（YAML 里可能有 NUL 吗？理论上可以，且长度显式更安全）。
3. **回调用 `extern "C"` 函数指针 + `void* user_data`**，Rust 侧包成 `Hooks`。
4. **panic 必须被拦住**：每个 `extern "C"` 入口都 `std::panic::catch_unwind`，否则 UB。
5. **不要在 FFI 线程里 block**：`apply_config` 需要构造 Snapshot，可能读文件/网络；要么在调用方线程上同步完成（慢但可预测），要么返回 future 句柄。第一版选同步，并在文档里说明"配置大会有 50–500ms 阻塞"。

### 3.2 与 Go 版的缝对照

| Go 的缝 | Rust FFI | 用途 |
| --- | --- | --- |
| `dns.DefaultQueryNotify` | `skyward_set_dns_hook` | 面板的 DNS 查询日志（含 initiator、upstream、cached） |
| `tunnel/statistic.DefaultRequestNotify` | `skyward_set_connection_hook` | 应用侧连接列表（用于按 App 分流展示） |
| `hub/executor.DefaultProviderLoadedHook` | `skyward_set_provider_hook` | 订阅加载进度条 |
| `component/updater.GeoUpdateHook` | `skyward_set_geo_hook` | Geo 更新提示 |
| `adapter.UrlTestHook` | `skyward_set_urltest_hook` | 手动测速的 UI 反馈 |
| `component/proxydialer.DefaultLoopNotify` | `skyward_set_loop_hook` | 报告 `dialer-proxy` 成环 |
| `hub/route.SwitchProxiesCallback` | `skyward_set_switch_hook` | 记录用户切换节点（写审计/统计） |
| `component/dialer.DefaultSocketHook` | `skyward_set_socket_hook` | Android 上给 socket 打 `VpnService.protect()` 标记 |
| `component/process.DefaultPackageNameResolver` | `skyward_set_package_resolver` | Android 上把 UID 映射成包名 |
| `component/dialer.DefaultInterfaceFinder` | `skyward_set_interface_finder` | 应用决定出站走哪个网卡 |
| `hub/route.SetEmbedMode(true)` | `SkywardOptions.embed_mode` | 嵌入式模式下禁用 restart/upgrade/PATCH 配置 |
| `--inbound` 标志 | `skyward_start_inbound()` | 是否自动开监听器 |

最后两条很多余但很关键：Go 版在 Android 构建里通过 `hub/route/patch_android.go` 的 `init()` 把 embed 模式打开——这是编译期魔法。Rust 版改成显式参数，行为更可控。

### 3.3 TUN 的交接

应用已经开了 TUN 设备（Android `VpnService`、iOS `NEPacketTunnelProvider`、桌面端自己拉 tun），Rust 版通过 fd 接收：

```rust
pub struct SkywardOptions {
    pub tun_fd: i32,            // -1 表示无 TUN
    pub tun_mtu: u32,
    pub tun_stack: TunStack,    // System | Smoltcp
    pub embed_mode: bool,
    pub home_dir: *const c_char,
}
```

这与 Go 版当前的现实一致：`hub.StartInbound` 不启动 TUN，TUN 由宿主负责。

## 4. CLI（`skywardd`）

除了 FFI，还要有一个可执行的二进制用作：

- CI 里的冒烟测试（`skywardd -t -f config.yaml`）
- 开发调试（`skywardd -d ./data -f config.yaml -inbound`）
- 基准测试（`bench/tunnel_bench.sh --core ./skywardd`）

参数与 Go 的 `main.go` 对齐（子集）：

| 参数 | 等价 Go 参数 |
| --- | --- |
| `-d <dir>` | `-d` |
| `-f <file>` | `-f` |
| `-config <base64>` | `-config` |
| `-t` | `-t` |
| `-v` | `-v` |
| `-inbound` | `-inbound` |
| `-ext-ctl <addr>` | `-ext-ctl` |
| `-secret <s>` | `-secret` |
| `-m` | `-m`（geodata 模式） |

子命令 `convert-ruleset` / `generate` / `age` 在 M6 之后单独做（或直接建议用 Go 版）。

## 5. 生命周期与关停

Go 版在 `main` 里 `defer executor.Shutdown()`，收到 `SIGINT/SIGTERM` 时退出；`SIGHUP` 重新解析配置。

Rust 版：

```rust
pub struct Skyward {
    runtime: Runtime,           // 由宿主决定是否拥有
    tunnel: Arc<Tunnel>,
    inbounds: ListenerManager,
    api: ApiServer,
    hooks: Hooks,
}

impl Skyward {
    pub async fn shutdown(self) {
        // 顺序：先停 API（否则面板会看到半死的状态）
        self.api.stop().await;
        // 再停入站（拒绝新连接）
        self.inbounds.close_all().await;
        // 最后取消所有连接与 DNS 服务
        self.tunnel.cancel_all();
    }
}
```

**关闭顺序不能反**：先停入站会让正在通过 API 看连接列表的面板看到"连接瞬间清空"，体验上像崩溃。
