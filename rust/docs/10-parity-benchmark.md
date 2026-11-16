# 10 · 等价性与性能验证

重写的失败模式不是"跑不起来"，而是"跑起来但和原来不一样"。这一份定义怎么证明"一样"。

## 1. 三类验证

| 类型 | 对象 | 方法 | 阻断级别 |
| --- | --- | --- | --- |
| 行为等价 | 规则、配置、API | 同一输入两版对比（决策表 / 快照） | 必须全绿 |
| 协议互通 | 出站与入站 | 同一服务端，两版客户端；字节级对比 | 必须全绿 |
| 性能 | 启动、吞吐、内存 | 同机基准，中位数 + 离散度 | 有阈值，超出需说明 |

## 2. 规则对拍（`cargo xtask parity rules`）

### 2.1 输入

一份"用例表"，YAML：

```yaml
# xtask/parity/rules.yaml
config: ../testdata/rules/600-rules.yaml   # 600 条规则，取自 bench/startup_test.go 的形态
cases:
  - name: domain-exact
    metadata:
      network: tcp
      host: "a.example.com"
      dest: { ip: "93.184.216.34", port: 443 }
      src: { ip: "10.0.0.2", port: 51234 }
    expect: "group-00"
  - name: ip-no-resolve
    metadata:
      network: tcp
      host: "b.example.com"
      dest: { ip: "10.0.5.7", port: 80 }
    params: { no_resolve_hit: true }
    expect: "DIRECT"
  - name: geoip-src
    ...
```

### 2.2 执行

```
xtask parity rules
  ├─ 用 Go 版编译一个 harness：cmd/parity-rules
  │    读 cases.yaml → 对每条 case 构造 C.Metadata → tunnel.resolveMetadata（或直接 rules 匹配）
  │    输出 JSON：[{name, adapter, rule_payload}]
  ├─ 用 Rust 版编译 harness：skyward-parity
  │    同样输入 → 同样输出
  └─ diff 两份 JSON；不一致的打印 case 名与两边的 (adapter, payload)
```

**必须覆盖的边界用例**（每类至少一条）：

| 类别 | 用例 |
| --- | --- |
| 域名后缀误伤 | `evilsite.com` 不应命中 `DOMAIN-SUFFIX,site.com` |
| 大小写 | `Example.COM` 与 `example.com` 等价 |
| 尾点 | `example.com.` 的处理（Go 的 trie 明确拒绝尾点，但配置里出现时行为要对齐） |
| 通配 | `*.example.com` 不匹配 `example.com` 本身；`+.example.com` 匹配子域与自身 |
| 正则 | `DOMAIN-REGEX` 的 payload 含逗号 |
| IP 惰性解析 | 域名规则在后、IP 规则在前时的**顺序语义** |
| `no-resolve` | 带该参数时不得触发 DNS |
| src 规则 | `SRC-IP-CIDR` 必须用源地址，且会交换 metadata（Go 的 `SwapSrcDst`） |
| 逻辑规则 | `AND,((DOMAIN,x),(NETWORK,tcp)),DIRECT` 的嵌套与短路 |
| PROCESS 规则失败 | 进程查找失败时"不命中"而非报错 |
| RULE-SET 循环 | 规则集引用自身时不得栈溢出 |
| MATCH 不在末尾 | `MATCH` 出现在中间时，后面的规则不可达 |
| Pass / Rematch | 命中后重新走一遍规则列表 |
| UDP 组不支持 | 命中不支持 UDP 的组时**跳过该条**继续匹配 |

### 2.3 规模

- 手工边界用例：约 100 条。
- 自动生成用例：600 条规则 × 200 个随机域名/IP，用固定种子生成，保证两版看同一批输入（Go harness 读同一份生成文件）。

## 3. 配置对拍（`cargo xtask parity config`）

对 `docs/config.yaml`（仓库官方示例，144 KB）以及 20 份真实订阅样本：

```
               Go                           Rust
parse  →  ConfigSummary JSON        parse  →  ConfigSummary JSON
```

`ConfigSummary` 只含可比较的**规范化**字段：

```json
{
  "general": { "mode": "rule", "logLevel": "info", "ipv6": true, "bindAddress": "*", "allowLan": false, "mixedPort": 10801 },
  "dns": { "enable": true, "enhancedMode": "fake-ip", "nameserver": ["https://doh.pub/dns-query"], "fakeIpRange": "198.18.0.1/16" },
  "proxies": [ { "name": "node-1", "type": "ss", "server": "1.2.3.4", "port": 8388, "udp": true } ],
  "groups": [ { "name": "auto", "type": "url-test", "members": ["node-1"] } ],
  "rules": [ { "type": "DomainSuffix", "payload": "example.com", "target": "auto" } ],
  "ruleProviders": { "geo": { "behavior": "domain", "count": 1000 } }
}
```

不比较的字段：ID（UUID 随机）、`updatedAt`、内部指针地址。

## 4. API 快照（`cargo xtask parity api`）

用 `insta` 快照测试：

```rust
#[tokio::test]
async fn api_proxies_snapshot() {
    let app = test_app("testdata/config-basic.yaml").await;
    let resp = app.get("/proxies").await;
    insta::assert_json_snapshot!(resp.json().await, { ".proxies.*.id" => "[uuid]" });
}
```

同时用 Go 版跑同一请求，生成 `snapshots/go/*.json`，并把两边做成 diff。第一版允许"字段集合相同、顺序不同"；到 M6 要求"逐字节相同"（除了 UUID 与时间）。

必须快照的端点：

```
GET  /                    GET  /version          GET  /configs
GET  /proxies             GET  /proxies/{n}      GET  /rules
GET  /providers/proxies   GET  /providers/rules  GET  /connections
GET  /dns/query?name=..   GET  /memory
```

## 5. 协议互通（`cargo xtask interop`）

复用仓库已有的 `test/`（Docker Compose）：

```yaml
# xtask/interop/docker-compose.yml —— 从 test/config 派生的服务端
services:
  ss:       { image: shadowsocks/shadowsocks-libev, ... }
  trojan:   { ... }
  vmess:    { image: v2fly/v2fly-core, ... }
  snell:    { ... }
```

对每个协议 × 每个用例：

| 用例 | 断言 |
| --- | --- |
| TCP pingpong（32 B × 100 次） | 内容一致、无丢包 |
| UDP pingpong（1 KiB × 100 次） | 同上 |
| 64 MiB 传输 | sha256 一致 |
| 错误密码 | 连接失败且错误类型为 `Auth`（不是 `Io`） |
| 不存在的目标 | 错误类型为 `Io`，且 5 秒内返回 |
| 半关闭 | 客户端 `shutdown(Write)` 后仍能读完响应 |

Go 版也跑同一套，作为基线（尤其是错误用例的耗时与错误文本）。

## 6. 性能基准

### 6.1 启动（对应 `bench/startup_test.go`）

Go 的基准：200 出站 / 12 组 / 600 规则的合成配置，测 `executor.ParseWithBytes`。

Rust 对应：

```rust
#[bench] // 或 criterion
fn parse_profile_600_rules(c: &mut Criterion) {
    let raw = synthetic_profile(200, 12, 600);
    c.bench_function("parse_600", |b| b.iter(|| config::parse(&raw)));
}
```

`xtask bench startup`: 跑两版，输出表：

| 阶段 | Go (ms) | Rust (ms) | 比值 |
| --- | ---: | ---: | ---: |
| YAML 解析 | | | |
| 规则编译 | | | |
| 出站构造 | | | |
| 合计 | | | |

目标：不慢于 Go（启动是应用冷启动的主要成本，Go 版已经优化过，Rust 至少不能退步）。

### 6.2 吞吐（对应 `bench/tunnel_bench.sh`）

直接复用这个脚本，`--core` 指两个二进制：

```bash
bench/tunnel_bench.sh --core ./skywardd-rust --mode proxy --size 256 --runs 9
bench/tunnel_bench.sh --core ./skywardd-go   --mode proxy --size 256 --runs 9
```

脚本的输出已经带 `median / cv / spread / stable`，直接记录即可。**判据**：

- `--mode proxy`（relay 路径）：Rust ≥ Go 的 95%。
- `--mode tun`：Rust ≥ Go 的 85%（smoltcp vs mips/gVisor 的现实差距）。
- 峰值 RSS：Rust ≤ Go 的 110%（协议栈少，但 tokio 每连接栈开销要注意）。

### 6.3 每连接开销

```bash
xtask bench conns --count 10000 --idle
```

测"1 万条空闲 TCP 连接"的 RSS 与建立耗时。这是移动端最关心的指标（用户挂着代理一整天）。

Go 版每 goroutine 栈起步 2 KiB（可增长），tokio task 自带 future 大小（我们的 `handle_tcp` future 若含大 `Metadata` 会膨胀）。**对策**：把大结构 `Box` 起来，避免 future 内联巨大状态机。

## 7. 持续集成

```yaml
# .github/workflows/rust.yml
jobs:
  check:
    steps:
      - cargo fmt --check
      - cargo clippy --all-targets -- -D warnings
      - cargo test --workspace
      - cargo test --workspace --features full
  parity:
    # 只在 push 到 skyward-rust 分支时跑，需要 Go 工具链
    steps:
      - cargo xtask parity rules
      - cargo xtask parity config
      - cargo xtask parity api
  interop:
    # 需要 Docker；夜间跑
    steps:
      - cargo xtask interop --suite p0
  bench:
    # 只在手动触发；数字写进 rust/docs/benchmarks.md
    steps:
      - cargo xtask bench startup
      - bench/tunnel_bench.sh ...
```

## 8. 记录

`rust/docs/benchmarks.md` 是一张**随时间累积**的表，每次发版追加一行：

| 日期 | 版本 | 启动 (ms) | proxy 吞吐中位数 (MiB/s) | tun 吞吐中位数 (MiB/s) | 峰值 RSS (MiB) | 备注 |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| | Go 1.10.0 | | | | | 基线 |
| | Rust 0.1.0 | | | | | M1，仅 mixed + direct |

这张表比任何设计文档都有说服力：它记录的是"每次改动到底带来了什么"。
