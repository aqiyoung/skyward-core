# 08 · 迁移路线图

原则：**每个里程碑都要有一个"能跑起来、能对拍"的产物**。不做"写三个月再联调"。

## 总览

| 里程碑 | 内容 | 出口准则 | 估算（人周） |
| --- | --- | --- | --- |
| M0 | 骨架：workspace、CI、`Tunnel` 空实现、最小 CLI | `cargo test` 全绿；`skywardd -v` 输出与 Go 同形 | 1 |
| M1 | 垂直切片：mixed 端口 + 规则 + DIRECT/HTTP/SOCKS 出站 + REST API 子集 | 用真实配置文件把 curl 打通；`/proxies`、`/configs`、`/connections` 可用 | 3–4 |
| M2 | 配置全量 + 规则全量 + ruleset(MRS) + DNS 基础 | `docs/config.yaml` 能解析；36 种规则对拍通过 | 4–5 |
| M3 | 出站 P0：SS / Trojan / VMess / VLESS / Snell / SSR / SOCKS / HTTP | 互通测试（Docker 服务端）全绿 | 8–10 |
| M4 | 组 + provider + 健康检查 + TUI/P1 协议（TUIC/Hysteria2/AnyTLS） | 订阅能加载、组能自动选、测速可用 | 6–8 |
| M5 | TUN（smoltcp）+ redir/tproxy + 入站全量 P0 | tun 模式下 `bench/tunnel_bench.sh` 可跑 | 6–8 |
| M6 | API 全覆盖 + DoH + storage + 迁移工具 | 面板（metacubexd）零改动可用 | 3–4 |
| M7 | FFI + 应用接入 + 性能收尾 | 应用能用 Rust 内核发版 | 4–6 |
| | | | **35–46** |

单人全职约 9–11 个月；两人并行可以压到 6–7 个月（M3 与 M4 可并行，M5 与 M6 可并行）。

## M0 · 骨架（1 周）

交付：

```
rust/
├── Cargo.toml
├── crates/skyward-core/src/{lib.rs, model/, tunnel/, io/, log/, sys/}
├── crates/skywardd/src/main.rs
├── .github/workflows/rust.yml
└── rust-toolchain.toml
```

工作项：

1. workspace + 12 个空 crate（`cargo check` 通过）。
2. `model/{metadata,proxy,rule,inbound,error}.rs` 骨架（可以先 `todo!()`，但类型签名定稿）。
3. `skywardd -v`、`-t`（读配置并解析成 `RawConfig` 后打印摘要）。
4. CI：`cargo fmt --check`、`cargo clippy -D warnings`、`cargo test`、`cargo build --release --target x86_64-unknown-linux-musl`（验证静态链接可行）。
5. 决定 `rust-toolchain.toml` 的版本（建议锁定 minor，例如 `1.83`，因为后面的 QUIC/TLS 依赖对版本敏感）。

出口：`cargo run -p skywardd -- -v` 输出 `Skyward Core v0.1.0 (rustc 1.83)`；`-t docs/config.yaml` 能解析不报错。

## M1 · 垂直切片（3–4 周）

这是最重要的一步：**打通一条完整的链路**，从此所有后续工作都是"往这个骨架上挂东西"。

范围：

- 入站：`mixed`（HTTP CONNECT + SOCKS5）
- 规则：DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / MATCH
- 出站：DIRECT / REJECT / HTTP / SOCKS5
- 隧道：完整的 `handle_tcp` 流程（preHandle / 嗅探先不做 / 匹配 / 拨号 / relay）
- 统计：连接注册 + 上下行计数
- API：`/`、`/version`、`/proxies`、`/configs`(GET)、`/connections`、`/traffic`(WS)

出口准则（可执行）：

```bash
# 用一个真实订阅里的配置
skywardd -d ./data -f ./config.yaml -inbound &
curl -x http://127.0.0.1:7890 https://example.com   # 必须成功
curl -s 127.0.0.1:9090/proxies | jq '.proxies | keys'
curl -s 127.0.0.1:9090/connections | jq '.connections | length'
```

## M2 · 配置与规则全量（4–5 周）

- `RawConfig` 90+ 字段全部实现，`docs/config.yaml` 作为 fixture。
- 36 种规则 + `sub-rules` + 逻辑规则。
- ruleset：yaml / text / mrs 三种格式。
- DNS：`udp` / `tcp` / `tls` / `https` 上游 + hosts + 缓存 + rcode。
- `component/resolver` 的"惰性解析"语义。
- 对拍工具 `xtask parity rules`（见 10）。

出口：用 Go 版的 600 条规则配置，两版对同一批 `Metadata` 给出**完全相同的 adapter**（100 个用例，含边界）。

## M3 · 协议 P0（8–10 周）

按此顺序，每个协议都要"互通测试 + 单元测试 + 一个 Go 生成的测试向量"：

1. Shadowsocks（AEAD + 2022）
2. Trojan（TCP + UDP）
3. VMess（AEAD，含 WS/gRPC 传输）
4. VLESS（含 Reality，先 boring 后端）
5. SSR（origin/plain 混淆）
6. Snell（v4/v5，v6 视时间）
7. WireGuard（smoltcp 或 boringtun + 最小栈）

出口：`xtask interop --suite p0` 全绿；每个协议 64 MiB 传输无错误。

## M4 · 组与 provider（6–8 周，可与 M3 并行）

- 5 种组（select / url-test / fallback / load-balance / relay）。
- provider 四种 vehicle + 定时更新 + ETag + 健康检查 + 订阅信息。
- `override`（不含 `override-expr`）。
- 持久化：选中项、fake-ip、storage（新格式；Go 迁移工具另做）。
- P1 协议：TUIC、Hysteria2、AnyTLS、Socks4。

出口：导入一份 300 节点的真实订阅，`url-test` 组 10 秒内选出最快节点，`/providers/proxies` 字段与 Go 版一致。

## M5 · TUN 与透明代理（6–8 周）

- `smoltcp` 栈接入：TCP/UDP/ICMP + DNS 劫持。
- Linux：`tproxy`（`IP_TRANSPARENT`）、`redir`（`SO_ORIGINAL_DST`）。
- macOS `utun`、Windows Wintun（只做设备接入，不做路由）。
- 用现成的 `bench/tunnel_bench.sh` 对比 Go 版 mips 栈。

出口：`--mode tun` 的基准能跑完 9 次，中位数与 Go 版差距 < 15%（这是"可接受"线；超过就要分析是栈的问题还是 relay 的问题）。

## M6 · API 全覆盖（3–4 周）

- 全部路由逐一对齐（45 条，清单见 [appendix/D-controller-routes.md](appendix/D-controller-routes.md)）。
- `/logs`、`/traffic`、`/connections` 三条 WS。
- DoH 入口、`/storage`、`/ui` 静态托管。
- 迁移工具：读 Go 的 bbolt → 写 Rust 的存储（见 05 §5）。

出口：metacubexd 面板连上 Rust 内核，所有页面正常，切换节点、测速、看日志、看连接都工作。

## M7 · FFI 与应用接入（4–6 周）

- `skyward-ffi` 全表面 + panic 拦截 + 内存泄漏检查（`valgrind` / ASan）。
- 应用侧改动：替换 `.so`/`.a`，接 hook。
- 双内核并行运行（灰度）：应用可以在两个内核间切换，用于线上对比。
- 性能收尾：relay 缓冲、`splice`（opt-in）、`SO_REUSEPORT`。

出口：应用的一个测试版本用 Rust 内核发布，崩溃率与内存占用不高于 Go 版。

## 并行开发约定

1. **crate 边界即分工边界**。一个人做 `skyward-proxy::trojan`，另一个人做 `skyward-rules`，不会打架。
2. **`model` 只由一个人改**。类型签名变更必须走 PR 评审，因为它影响所有 crate。
3. **每个 PR 必须有测试**。协议 PR 必须有互通测试；规则 PR 必须有对拍用例；API PR 必须有响应快照。
4. **不留 TODO 在 `main` 分支**。未完成的功能用 `feature` gate 关掉并给出明确错误，而不是 `todo!()`（会 panic）。
5. **每周跑一次全量基准**，把数字记在 `rust/docs/benchmarks.md`（随时间累积的表，不进代码评审的必过项，但必须公开）。

## 风险与缓冲

路线图里有三处天然的风险点，各留了缓冲：

| 风险 | 影响 | 缓冲 |
| --- | --- | --- |
| Snell / MRS 无公开规范，只能读代码 | M3 可能超期 2 周 | 先做 SS/Trojan/VMess，Snell 可延后到 M4 |
| `smoltcp` 吞吐不及 gVisor | M5 基准不达标 | 基准门槛设为"不低于 Go 版 85%"，且可临时保留 Go 的 TUN 子进程 |
| `override-expr` 3k 行解释器 | M4 超期 | 第一版明确不支持，报错提示 |

详细风险登记见 [11-open-questions.md](11-open-questions.md)。
