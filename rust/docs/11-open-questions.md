# 11 · 待定事项与风险登记

## A. 需要产品/维护者拍板的问题

按"卡住后续工作的程度"排序。

### A1. 交付目标：库还是可执行文件？

Go 版两个都做（`main.go` 有 CLI，`.so` 给应用）。Rust 版如果只做 CLI，应用无法接入；只做 `.so`，则无法跑基准与 CI 冒烟。

**建议**：两个都做，但 `.so` 是主交付物，CLI 是调试工具（`skywardd`）。这决定 M0 的 CI 就要验证 `--target x86_64-unknown-linux-musl` 与 `-Ctarget-feature=+crt-static`。

### A2. ABI 兼容：能不能要求应用改代码？

如果应用侧可以改（推荐），FFI 就按本方案的 `skyward_*` 函数族设计；如果不能改，就得复刻 Go 版导出的符号——而本仓库里没有 `//export`（已确认 grep 无结果），说明 FFI 层在应用仓库里，那么**应用侧必须改**。这一点需要确认。

### A3. 编译产物大小预算

Go 版 `size.yml` 记录了三档：`full`（with_gvisor）、`trim`（去三个 mesh VPN）、`lean`（再去 fake-tcp）。Rust 版的对应目标应该是多少？

**建议**：`ss + trojan + vmess + vless + tun + api` 的 release（`opt-level="z"`、`lto="fat"`、`panic="abort"`、`strip`）目标 ≤ 8 MiB（每平台）。

### A4. 是否保留 `override-expr`

3,032 行解释器，只有高级用户用。第一版不支持会不会引起投诉？

**建议**：第一版不支持，但给出清晰错误 + 文档链接；如果反馈强烈再补。

### A5. TUN 栈的取舍

smoltcp 的吞吐低于 gVisor/mips。是否接受？还是继续沿用"Go 子进程跑 TUN"的过渡方案？

**建议**：先做 smoltcp，用 `bench/tunnel_bench.sh` 量化差距；若 < 85%，考虑混合方案（TUN 交给一个极小的 Go 辅助进程，隧道仍在 Rust）。

### A6. 缓存文件迁移

见 [05 §5](05-rules-providers.md)。三选一：只读 bbolt / 迁移工具 / 接受丢失。

**建议**：迁移工具（Go 侧 `-export`，Rust 侧 `-import`），一次性成本低、用户体验好。

## B. 风险登记册

| # | 风险 | 概率 | 影响 | 缓解 |
| --- | --- | --- | --- | --- |
| R1 | Snell 无规范，只能读 Go 代码 | 高 | M3 超期 1–2 周 | 放在 SS/Trojan/VMess 之后；先做 v4 |
| R2 | `regexp2` 的回溯语义无法用 `regex` 表达 | 中 | DOMAIN-REGEX / 过滤规则行为漂移 | 用 `fancy-regex`；不支持的语法在配置校验时明确报错 |
| R3 | Reality 需要 BoringSSL（不可纯 Rust） | 高 | 交叉编译复杂（Android/iOS） | 默认 feature 不含 reality；`--features reality` 才引入 `boring` |
| R4 | smoltcp 吞吐不足 | 中 | M5 基准不达标 | 见 A5 |
| R5 | `bbolt` 格式不兼容导致用户丢配置 | 高 | 升级体验差 | 见 A6 |
| R6 | QUIC 生态（quinn）与 Go 版行为差异（拥塞、0-RTT、MTU 探测） | 中 | TUIC/Hysteria2 性能或兼容性问题 | 先用默认拥塞，基准先行；必要时实现 BBR |
| R7 | FFI 的 panic / 内存泄漏 | 中 | 应用崩溃 | `catch_unwind` + ASan/valgrind CI + Miri 测关键 unsafe |
| R8 | API 字段细微不一致导致面板异常 | 高 | 用户体验差 | 快照对拍（M6 前就必须开始） |
| R9 | 移动端交叉编译（Android NDK / iOS） | 中 | 交付延期 | M0 就配好 `cargo-ndk` 与 `xcodebuild` 的最小验证 |
| R10 | 两套代码并行期间修 bug 要改两次 | 高 | 维护成本 | 在 M1–M3 期间**冻结 Go 版新功能**，只修安全与严重 bug；bug 修复先进 Rust 再回移（或反之，但要有一条规矩） |
| R11 | UDP 路径的 `try_send` 与 tokio 调度器交互 | 低 | 丢包率异常 | 压力测试（见 10 §6.3）+ 指标暴露 |
| R12 | `Arc<Snapshot>` 延迟回收导致内存峰值 | 中 | 大订阅 + 频繁重载时 RSS 抖 | 限制同时在飞的快照数（保留 2 个），旧快照的"长连接池"单独引用计数 |

## C. 明确不做的事

写下来是为了避免反复讨论：

1. **不做 Go 与 Rust 的进程内互调**（cgo 双向绑定）。复杂度远超收益，且会让内存模型混乱。
2. **不追求与 Go 版二进制兼容的缓存/配置文件**，只保证语义兼容 + 提供迁移路径。
3. **不支持 32 位 x86 与 MIPS**（Go 版支持，但那是历史包袱；Rust 版先做 amd64/arm64/armv7）。
4. **不实现 Go 版的 `test/` 全套协议测试**，只挑 P0 协议的互通用例。
5. **不保留 `common/xsync` 的 sharded map 语义**（Go 里是为了避免锁竞争，Rust 用 `DashMap`/`ArcSwap` 更直接）。

## D. 需要上游（mihomo）关注的事

Rust 版会与 Go 版并行一段时间，这意味着：

- 协议的新版本（例如 Snell v7、VMess 新加密）会被上游加入 Go 版，Rust 版要跟。
- Geo 数据格式（`geoip.dat` / `geosite.dat` / `ASN.mmdb` / MRS）是共享的，任何格式变化都会同时影响两边。
- 面板兼容性（API）是共享契约，任一方改动都要同步。

**建议**：在 Rust 版达到 M3 之后，把 `rust/` 目录的内容也纳入上游的 issue/PR 流程（如果维护者愿意），否则至少保持一个"格式变更时通知"的约定。

## E. 开放的技术选择（可在 M0 前定，也可推迟）

| 选择 | 选项 | 何时必须定 |
| --- | --- | --- |
| YAML 库 | `serde_yaml_ng` / `serde_norway` / `yaml-rust2` | M0（影响宽容解析的写法） |
| HTTP 客户端（出站 HTTP 代理、订阅下载） | `hyper` 自建 / `reqwest` | M1（订阅下载） |
| 正则 | `regex` / `fancy-regex` / `onig` | M2（DOMAIN-REGEX） |
| QUIC | `quinn` / `s2n-quic` | M4（TUIC） |
| IP 栈 | `smoltcp` / 自写 | M5（TUN） |
| 持久化 | `redb` / `sled` / 自写 KV / JSON 文件 | M4（provider 缓存） |
| 日志 | `tracing` + JSON / 自写轻量 | M0 |

每一项的建议已写在相关文档里；这里只是把"还没最终确认"的点集中起来，避免它们散落在各个章节里被忽略。
