# 00 · 现状盘点

写清楚"要重写什么"，比决定"用什么写"更重要。这份盘点全部来自本仓库代码，数字可复现。

## 1. 这是什么

`skyward-core` 是 mihomo（Clash.Meta）的一个分支，作为某个桌面/移动应用的**内核**：应用负责 UI、订阅编辑器、TUN 设备与进程环境，内核负责代理协议、规则匹配、DNS、以及给 UI 提供数据的 REST API。

关键事实（都能在代码里指到）：

- 内核被编译成库给应用用。`.github/workflows/size.yml` 的原话是"the linux binary is a proxy for the .so the app ships"，所以 Rust 版的第一交付物必须是 **一个可从 C/JNI 调用的 cdylib**，而不是一个只读配置文件的 CLI。
- 监听器不自动启动。`hub.StartInbound` 的注释："The app starts them itself, once it has brought its own tunnel up… a configuration that asks for the tunnel from the command line is a thing this fork does not do." 所以 Rust 版要把"启动"和"接管理"拆成两个显式调用。
- 内核里有大量**给宿主用的缝**（seam），不是公共 API 但语义上属于 ABI：DNS 查询回调、连接事件回调、provider 加载完成回调、测速回调、GeoIP 更新回调、dialer 环检测通知、以及 `hub/route.SetEmbedMode` 这类行为开关。见 [07-api-host.md](07-api-host.md)。
- `patch*.go` / `patch_*.go` 这 25 个文件不是补丁，是"按平台或按调用方替换实现"的挂载点。移植时它们要么变成 trait object 注入，要么变成 cfg 条件编译。

## 2. 数据流（一次 TCP 请求）

```
inbound listener (mixed/http/socks/tun/...)
  └─ 解析目标 → Metadata（含 InName / InUser / SpecialRules / Addition）
       └─ tunnel.HandleTCPConn
            ├─ isHandle(Type) 过滤（INNER / REDIR / TPROXY ... 的准入）
            ├─ preHandleMetadata：fake-ip 反查 host、hosts 改写、DNSMode 标记
            ├─ sniffer：从流首字节嗅出域名（TLS SNI / HTTP Host / QUIC）
            ├─ resolveMetadata → match(rules)
            │    ├─ 规则按序匹配，命中规则给出 adapter 名字（DIRECT / REJECT / 组名）
            │    ├─ Pass 规则 → 继续短路；Rematch 规则 → 换一组规则重来
            │    └─ UDP 且目标不支持 UDP → 跳过该条
            ├─ proxy.DialContext(metadata)（组会再向下委派，链条写回 Connection.Chains）
            ├─ statistic：注册 Tracker，统计上下行
            └─ relay：双向拷贝 + half-close（RelayContext 支持 ctx 取消）
```

UDP 路径不同：`HandleUDPPacket` 按 `metadata.Key()` 哈希到 N 个队列（容量 256，满了就丢包——QUIC 会把丢包读成拥塞），每个 worker 在 `nat.Table` 里按 key 找**已有会话**，找到就直接投递；找不到才做规则匹配、嗅探、创建 `PacketSender`。**稳态路径不重复做规则匹配**，这是刻意的，注释里写了原因。Rust 版必须保留这个性质。

## 3. 规模与分布（为什么不能一把梭）

| 区域 | 现状 | 结论 |
| --- | --- | --- |
| `transport/` 71,833 行 | 28 个协议目录；`sudoku` 13.6k、`openvpn` 13.5k、`tuic` 8.5k | 协议是长尾。Rust 版先做 5 个高频协议，其余按需 |
| `listener/` 21,484 行 | 20 种入站；`sing_tun` 2.5k 依赖 sing-tun/go 栈 | TUN 栈依赖 gVisor/mips/sing-tun，Rust 侧要换实现（见 04 §7） |
| `component/` 23,317 行 | 嗅探 3.5k、geodata 2.5k、dialer 1.2k、resolver 1.0k | 多数是可独立移植的"叶子"，适合早期并行 |
| `adapter/` 19,586 行 | 28 种出站 + 5 种组 + provider 4.6k | provider（订阅/健康检查）比协议本身更复杂 |
| `common/` 17,854 行 | `xsync` 3.9k、`net` 2.7k、`convert` 2.0k | 一半是 Go 标准库缺失的补丁，Rust 标准库/生态已有，**不需要 1:1 移植** |
| `rules/` 3,091 行 | 36 种规则 + MRS 读写 | 逻辑简单但语义细节多，是最值得先做对的部分 |
| `dns/` 4,484 行 | udp/tcp/tls/https/quic/dhcp/rcode/system 八种上游 | 中间件链清晰，可原样映射成 tower 层 |
| `hub/` 2,955 行 | 45 条 REST 路由 + WebSocket 流 | 面板兼容性要求 API 逐字段一致，是"对拍"重点 |

`common/` 里大约一半代码在 Rust 里会消失：

| Go | 行数 | Rust 处置 |
| --- | ---: | --- |
| `common/xsync` | 3,893 | `HashMap` + `RwLock` / `dashmap`；Go 泛型 map 的 sharded 实现不需要照搬 |
| `common/orderedmap` | 1,844 | `indexmap`（YAML 键序也是它） |
| `common/structure` | 1,236 | `serde` + 自定义 `Deserializer`（宽容类型转换自己写一层） |
| `common/maphash`、`murmur3` | 1,043 | `std::hash` / `ahash`；仅当要和线上数据格式对齐时才复刻 |
| `common/net` | 2,725 | tokio 的 `AsyncRead/AsyncWrite` + 自己的 `BufConn`/`CachedConn`/`EarlyConn` 包装（这几个是真需要） |
| 其余（queue/lru/arc/pool/once/singleflight…） | ~3,700 | `moka`、`arc-swap`、`once_cell`、`tokio::sync::OnceCell`、`futures::future::Shared` 等直接替代 |

## 4. 已经能确认的"必须行为"

移植时最容易出错的地方，先列出来（来源都在注释里）：

1. **热重载是快照替换，不是原地改**。`tunnel/patch.go` 的 `AllProxies()` 用 copy-on-write 发布整张表，注释说明"rebuild 一次在大订阅上是几 MB 垃圾"。Rust 版用 `ArcSwap<Snapshot>` 天然得到这个语义。
2. **UDP 满队列丢包而不是阻塞**。丢包被 QUIC 读作拥塞，阻塞会把问题扩大。Rust 用 `try_send`，不许 `await`。
3. **规则匹配里的 IP 解析是惰性的**。`RuleMatchHelper.ResolveIP` 是一个可空回调，只有走到 IP 规则才触发解析；`no-resolve` 直接把它置空。Rust 版不能写成"先解析再匹配"。
4. **Pass / Rematch 是规则层的控制流**，不是出站类型。`match()` 里对 `C.Pass` 会 `continue GetRules`，对 `C.Rematch` 会跳出重来一遍。
5. **`Metadata` 会被 sniff 修改**，且 fake-ip 命中时 `DstIP` 会被清空、`DNSMode` 变成 `DNSFakeIP`。这些字段下游（规则、日志、API）都读。
6. **DNS 应答要补 EDNS0**（RFC 6891），UDP 要按客户端声明的 size 截断并置 TC 位。`dns/server.go` 与 `dns/service.go` 各做一半。
7. **测速是 HEAD 请求**，默认 URL 是 `https://www.gstatic.com/generate_204`；`unified-delay` 会发第二次请求重新计时。
8. **`dialer-proxy` 可能成环**，Go 版用一次拨号内的步数记录检测并报错。Rust 版用 task-local 或 context 结构体同样实现。

## 5. 重写的边界

**要重写**：隧道、规则、DNS、协议、配置、API、provider。也就是"内核"的全部。

**不重写**：

- 应用的 UI 与订阅编辑逻辑（不在本仓库）。
- TUN 设备控制面（`sing_tun` 里的路由/iptables/网卡配置）。Rust 版实现 L3 包处理与栈，但"谁开网卡、谁加路由"仍由宿主决定 —— 这与 Go 版当前行为一致（CLI 模式下 `-inbound` 都不自动开 TUN）。
- 第三方 CLI 子命令（`convert-ruleset`、`generate`、`age`）可以在第一期用独立小工具代替，不占主进程预算。

**暂时不追的功能**（明确挂起，见 04 §8）：`easytier`、`tailscale`、`zerotier`、`openvpn`、`mieru`、`sudoku`、`tlsmirror`、`trusttunnel`。它们在 Go 版里合计约 25k 行，且各自带着几百 KB 的第三方栈。
