# Rust 重写：设计与迁移方案

`rust/` 目录是 `skyward-core` 的 Rust 版方案，与 Go 代码并列存在。目前只有文档，没有 Rust 代码；第一个交付代码的里程碑是 M0。

- 入口：[`rust/README.md`](rust/README.md)
- 现状盘点与重写边界：[`rust/docs/00-overview.md`](rust/docs/00-overview.md)
- 架构与 crate 划分：[`rust/docs/01-architecture.md`](rust/docs/01-architecture.md)
- 路线图与工作量：[`rust/docs/08-migration-plan.md`](rust/docs/08-migration-plan.md)
- 等价性验证与基准：[`rust/docs/10-parity-benchmark.md`](rust/docs/10-parity-benchmark.md)

技术栈：tokio + hyper/axum + rustls（指纹伪装场景用 BoringSSL），GPL-3.0，与 Go 版一致。

方案要点：

| 项 | 结论 |
| --- | --- |
| 交付形态 | 先文档、后代码；最终交付 cdylib 给应用 + `skywardd` CLI 供调试与基准 |
| crate 数 | 12 个（core / rules / config / dns / transport / proxy / inbound / provider / api / ffi / cli / xtask） |
| 协议范围 | P0 六个（SS、Trojan、VMess、VLESS、Snell、SSR）+ P1 三个（TUIC、Hysteria2、AnyTLS）；mesh VPN、OpenVPN、Sudoku、Mieru 明确挂起 |
| 周期 | 单人 35–46 人周（9–11 个月），双人并行 6–7 个月 |
| 验收 | 规则决策表对拍、配置摘要对拍、API 快照、协议互通、同机基准五项全绿 |
