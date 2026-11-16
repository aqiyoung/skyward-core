# Skyward Core — Rust 重写

这个目录是 `skyward-core` 的 Rust 版设计与迁移方案。Go 代码保持原样，Rust 版本在这里从零生长，两者在切换完成前并行存在。

文档先行：本目录当前只有文档，**没有 Rust 代码**。第一个提交代码的里程碑是 M0（见 [08-migration-plan.md](docs/08-migration-plan.md)）。文档里的 Rust 片段是设计示例，不是可直接编译的源码；从 M0 开始，示例会被真正的 crate 取代。

## 已确定的决策

| 决策 | 结论 | 出处 |
| --- | --- | --- |
| 交付形态 | 设计/迁移文档先行，代码按里程碑落地 | 本目录 |
| 代码位置 | `rust/` 子目录，与 Go 代码并列，互不干扰 | 本目录 |
| 异步运行时 | tokio（multi-thread） | [03-runtime.md](docs/03-runtime.md) |
| HTTP 栈 | hyper 1.x；REST API 用 axum；出站 HTTP 走 hyper + 自建连接池 | [07-api-host.md](docs/07-api-host.md) |
| TLS | rustls 为主；需要客户端指纹伪装（uTLS 等价物）时用 BoringSSL（`boring`） | [04-protocols.md](docs/04-protocols.md) |
| 许可 | GPL-3.0，与 Go 版一致（下游命名限制是上游 mihomo 的条款，不随派生代码继承，但本项目仍不欢迎同名分支） | [11-open-questions.md](docs/11-open-questions.md) |

## 文档索引

| 文档 | 内容 |
| --- | --- |
| [00-overview.md](docs/00-overview.md) | 现状盘点：Go 代码的真实规模、分层、热路径；为什么要重写、重写的边界 |
| [01-architecture.md](docs/01-architecture.md) | Rust 架构总览：crate 划分、依赖方向、Cargo workspace 全文 |
| [02-domain-model.md](docs/02-domain-model.md) | 核心类型与 trait：`Metadata`、`Proxy`、`Rule`、`Tunnel`、`Inbound`、`Provider`、错误与钩子 |
| [03-runtime.md](docs/03-runtime.md) | 运行时与并发：任务模型、TCP relay、UDP 分片队列与 NAT 会话、热重载快照、内存与缓冲池 |
| [04-protocols.md](docs/04-protocols.md) | 协议层：出站/入站全清单、分阶段实现顺序、依赖库映射、逐协议风险 |
| [05-rules-providers.md](docs/05-rules-providers.md) | 规则引擎与 provider：36 种规则的匹配语义、ruleset（MRS）、订阅、override |
| [06-config-dns.md](docs/06-config-dns.md) | 配置解析（宽容解码、默认值、热更新）与 DNS（协议、fake-ip、策略、中间件链） |
| [07-api-host.md](docs/07-api-host.md) | 外部控制器 REST/WS API、DoH 入口、嵌入式宿主接口（FFI）与 Go 的缝（hook） |
| [08-migration-plan.md](docs/08-migration-plan.md) | 迁移路线图 M0–M7、每阶段出口准则、工作量估算、并行开发约定 |
| [09-porting-playbook.md](docs/09-porting-playbook.md) | 逐包移植手册：Go 惯用法到 Rust 惯用法的对照与示例 |
| [10-parity-benchmark.md](docs/10-parity-benchmark.md) | 等价性验证与性能基准：决策表对拍、API 快照、启动与吞吐测量 |
| [11-open-questions.md](docs/11-open-questions.md) | 待定事项与风险登记册 |
| [appendix/README.md](docs/appendix/README.md) | 由 Go 源码生成的附录：规则类型、协议清单、配置键全集、REST 路由表、代码规模 |

## 现状速览

Go 内核：1018 个文件、174,337 行（非测试 136,721 行）。其中 `transport/` 一个包就占 41%。

| 包 | 文件 | 行数 | 非测试行数 |
| --- | ---: | ---: | ---: |
| `transport` | 317 | 71,833 | 56,342 |
| `component` | 174 | 23,317 | 18,387 |
| `listener` | 158 | 21,484 | 15,098 |
| `adapter` | 75 | 19,586 | 18,727 |
| `common` | 132 | 17,854 | 10,997 |
| `dns` | 25 | 4,484 | 4,173 |
| `rules` | 37 | 3,091 | 2,917 |
| `hub` | 24 | 2,955 | 2,955 |
| `config` | 6 | 2,456 | 2,274 |
| `constant` | 33 | 1,886 | 1,809 |
| `tunnel` | 10 | 1,824 | 1,824 |
| `test` | 12 | 2,302 | 50 |
| 根目录 / `bench` / `log` / `ntp` / `context` | 15 | 1,265 | 1,168 |
| **合计** | **1,018** | **174,337** | **136,721** |

协议面：5 种出站组之外有 28 种出站类型、20 种入站类型、36 种规则语法名、45 条 REST 路由。这不是一次能写完的移植，本方案按"先切片跑通、再按热度补全、最后清长尾"推进。
