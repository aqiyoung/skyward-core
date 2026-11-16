# 05 · 规则与 Provider

## 1. 规则的分层

Go 版三层，Rust 版保留同样的分层，因为每一层解决不同问题：

```
rules/parser.go            →  字符串 → Box<dyn Rule>          （结构解析）
rules/common/*.go          →  单条规则的匹配语义              （叶子）
rules/logic/logic.go       →  AND / OR / NOT / SUB-RULE 组合   （复合）
rules/provider/*.go        →  RULE-SET 背后的数据集           （外部）
rules/parser.go(ParseRulePayload) →  "TP,PAYLOAD,TARGET,P1,P2" （语法）
```

**语法与语义分开**很重要：Go 的 `ParseRulePayload` 里有一段特殊处理（`MATCH` 没有 payload；`NOT/OR/AND/SUB-RULE/DOMAIN-REGEX/PROCESS-*-REGEX` 的 payload 里可以含逗号，所以 target 取最后一段）。这段逻辑必须逐字移植，否则含逗号的 DOMAIN-REGEX 会解析错。

```rust
// crates/skyward-rules/src/syntax.rs
pub struct RawRule<'a> {
    pub kind: &'a str,
    pub payload: Cow<'a, str>,
    pub target: Option<&'a str>,
    pub params: SmallVec<[&'a str; 2]>,
}

pub fn split_rule(raw: &str) -> Option<RawRule<'_>> {
    let mut parts: SmallVec<[&str; 4]> = raw.split(',').map(str::trim).collect();
    let kind = parts[0].to_ascii_uppercase();
    match kind.as_str() {
        "MATCH" => Some(RawRule { kind: "MATCH", payload: "".into(), target: parts.get(1).copied(), params: SmallVec::new() }),
        "NOT" | "OR" | "AND" | "SUB-RULE" | "DOMAIN-REGEX"
        | "PROCESS-NAME-REGEX" | "PROCESS-PATH-REGEX" => {
            // payload 可含逗号，target 是最后一段
            let target = parts.pop();
            Some(RawRule { kind: &kind, payload: parts[1..].join(",").into(), target, params: SmallVec::new() })
        }
        _ => {
            let payload = parts.get(1).copied().unwrap_or("").into();
            let target = parts.get(2).copied();
            let params = parts.iter().skip(3).copied().collect();
            Some(RawRule { kind: &kind, payload, target, params })
        }
    }
}
```

（注意：`kind` 需要 `String` 而不是借用 `raw`，上面的写法为了展示结构简化了；实际实现里 `kind` 直接匹配到 `RuleKind` 枚举即可，无需分配。）

## 2. 36 种规则的实现表

| 规则 | 数据 | 匹配 | 易错点 |
| --- | --- | --- | --- |
| DOMAIN | `Box<str>` | `host == payload`（大小写不敏感） | 必须先小写化；`host` 可能来自 sniff |
| DOMAIN-SUFFIX | `Box<str>` | `host.ends_with(".suffix") \|\| host == suffix` | **不是** `ends_with(suffix)`，否则 `evilsite.com` 会命中 `site.com` |
| DOMAIN-KEYWORD | `Box<str>` | `host.contains(keyword)` | |
| DOMAIN-REGEX | `regex::Regex` | `is_match(host)` | Go 用 `regexp2`（回溯），Rust `regex` 不支持回溯。需要回溯语义的写法（如带反向引用）要么改用 `fancy-regex`，要么在配置校验时拒绝 |
| DOMAIN-WILDCARD | `wildcard::Pattern` | 自己实现的 `*.` / `+.` 通配 | Go 是 `component/wildcard`（基于 trie），语义要逐例对拍 |
| GEOSITE | 预编译 `DomainSet` | `set.contains(host)` | 需要读 `geosite.dat`（protobuf）与 MRS |
| GEOIP | `IpCidrSet` | `set.contains(ip)` | 需要 `mmdb` 或 `geoip.dat`；`src` / `no-resolve` 参数 |
| IP-CIDR / IP-CIDR6 | `ipnet::IpNet` | `net.contains(&ip)` | IPv4-mapped IPv6 要先 unmapped |
| IP-SUFFIX | 掩码比较 | 与 Go 的 `IpSuffix` 一致（非 CIDR 的位前缀） | |
| IP-ASN | `maxminddb` ASN 库 | `asn == payload` | 需要 `ASN.mmdb` |
| SRC-PORT / DST-PORT / IN-PORT | `PortRange` | `contains(port)` | 支持 `80`/`8000-9000`/`80,443` |
| DSCP | `u8` | 相等 | |
| IN-TYPE / IN-USER / IN-NAME | 字符串 | 相等 | `in_name` 默认值参与匹配 |
| NETWORK | `Network` | 相等 | `tcp` / `udp` |
| UID | `u32` | 相等 | 仅 Android/Unix |
| PROCESS-NAME / PATH（+REGEX/WILDCARD ×2） | 字符串/正则 | 惰性 `find_process()` | 失败时**规则不命中**，不是报错 |
| REMATCH-NAME | 字符串 | `metadata.rematch_name` | |
| RULE-SET | provider 引用 | 委派给 provider | 循环引用（RULE-SET 里再 RULE-SET）要检测 |
| SUB-RULE | `Vec<Box<dyn Rule>>`（命名集） | 依次匹配 | 子规则集来自 `sub-rules:` 配置 |
| AND / OR / NOT | `Vec<Box<dyn Rule>>` | 组合 | **短路语义**与 Go 一致；NOT 只作用于单条 |
| MATCH | 无 payload | 恒真 | 必须放最后一条，但要允许放中间（Go 允许，语义是"到此为止"） |

Rust 侧统一用枚举而非 `dyn Rule`，让编译器帮我们把 36 种都覆盖到，并让匹配走 `match` 而不是虚调用：

```rust
pub enum Rule {
    Domain(DomainRule),
    DomainSuffix(DomainSuffixRule),
    // ... 36 个变体
    Logic { op: LogicOp, children: Box<[Rule]> },
    RuleSet { provider: String, adapter: AdapterName, src: bool, no_resolve: bool },
    Match { adapter: AdapterName },
}

impl Rule {
    #[inline]
    pub fn matches(&self, m: &Metadata, h: &mut MatchHelper<'_>) -> Option<&AdapterName> {
        match self {
            Rule::DomainSuffix(r) => r.matches(m).then(|| &r.adapter),
            // ...
        }
    }
}
```

用枚举而不是 `Box<dyn Rule>` 的收益在热路径上很明显：规则列表每连接走一遍，虚调用会阻止内联，且 `match` 天然带分支预测友好的布局。代价是新增规则要改 `enum`——但规则集合本来就不常变。

## 3. 规则列表的编译

Go 版在 `tunnel` 里维护 `[]C.Rule`，线性扫描。这对 600 条规则是可接受的（`bench/startup_test.go` 用的就是 600 条）。Rust 版第一版**照抄线性扫描**，不要过早优化。

但在 M6 可以加一个**按规则类型分桶的前置优化**：

```rust
pub struct RuleSet {
    rules: Box<[Rule]>,
    // 可选优化：把纯域名/纯 IP 规则抽出来建索引，但要保持"第一条命中"的语义
    domain_index: Option<DomainIndex>,
}
```

前提是先证明它值：用 `bench/startup_test.go` 同形的配置（200 出站 / 12 组 / 600 规则）做基准。若线性扫描的 p99 已 < 5µs，则不做。

## 4. RuleSet 数据格式

Go 版支持三种 `format`（`constant/provider/interface.go`）：

- `yaml`：`payload:` 列表，两种形态（纯字符串列表 / `{DOMAIN,x}` 对象列表）
- `text`：每行一条规则
- `mrs`：zstd 压缩的二进制（`rules/provider/mrs_reader.go`，魔数 `MRS\x01`）

以及三种 `behavior`：`domain` / `ipcidr` / `classical`。

Rust 版：

```rust
pub enum RuleFormat { Yaml, Text, Mrs }

pub trait RuleStrategy: Send + Sync {
    fn behavior(&self) -> RuleBehavior;
    fn insert(&mut self, line: &str) -> Result<(), Error>;
    fn finish(&mut self) -> Result<(), Error>;
    fn matches(&self, m: &Metadata, h: &mut MatchHelper<'_>) -> bool;
    fn count(&self) -> usize;
}
```

三个实现：

| behavior | 结构 | 插入复杂度 | 匹配复杂度 |
| --- | --- | --- | --- |
| domain | `DomainSet`（succinct 或简单后缀 trie） | O(len) | O(len) |
| ipcidr | `IpCidrSet`（按前缀长度分桶 + 前缀树） | O(bits) | O(bits) |
| classical | `Vec<Rule>` + 线性 | O(1) | O(n) |

**MRS 读取**：`MRS` 是压缩的规则集，作者是 MetaCubeX。第一版用 `zstd` + 按 Go 的读取顺序实现（`mrs_reader.go` 里有完整布局）；写入（`mrs_converter.go` / `convert-ruleset` 子命令）可以后置。

## 5. Provider

Go 的 `adapter/provider`（4,596 行）比"下载一份列表"复杂得多，它包含：

| 能力 | 说明 | Rust 对应 |
| --- | --- | --- |
| 四种 vehicle | file / http / inline / compatible（把订阅链接转 Clash 配置） | `Vehicle` 枚举 |
| 定时更新 + 指数退避 | `component/slowdown` | `tokio::time` + `Backoff` |
| ETag / Last-Modified | `component/resource` 与 `profile/cachefile` | `http` 条件请求 + 本地缓存文件 |
| 健康检查 | 定时 HEAD 测速、`expectedStatus`、按 URL 分别记录 | `HealthCheck` 任务 |
| 过滤与覆盖 | `filter` / `exclude-filter` / `exclude-type`（`regexp2`） | `regex`（不支持回溯，见 §2 注） |
| `override` | 对每个 proxy mapping 做字段改写 | 直接改 `serde_yaml::Value` |
| `override-expr` | **yq 子集**，3,032 行自写解释器 | 见 §6 |
| 订阅信息 | 解析 `subscription-userinfo` 响应头（流量、到期） | `SubscriptionInfo` |
| 持久化 | 选中的组、fake-ip 表、ETag、storage | `component/profile/cachefile`（bbolt） |

### 缓存文件格式

Go 用 `bbolt`（B+ 树 KV，单文件）。Rust 版第一版**不兼容 bbolt 文件格式**，会带来一个问题：从 Go 版升级到 Rust 版后，用户的"选中节点""fake-ip 映射""storage（面板设置）"会丢。

三种处理：

1. 实现 bbolt 读（只读，~300 行，格式公开且稳定），迁移后写自己的格式；
2. 提供一个一次性迁移工具（Go 版 `-migrate` 子命令导出 JSON，Rust 版导入）；
3. 直接接受丢失（面板会重建，fake-ip 会重新分配）。

**建议 (2)**：成本最低、风险最小，且不把 Rust 版绑死在别人的文件格式上。见 11 的风险登记。

## 6. override-expr

这是整个仓库里最"意外"的一块：`adapter/provider/override_expr.go` 3,032 行，实现了一个 yq 子集（赋值、`|=`、`+=`、`del()`、`select()`、管道、通配路径、数组索引…），用于在订阅之上批量改写节点。

迁移策略：

- **第一版不实现**。配置里出现 `override-expr` 时给出明确错误："this build does not support override-expr; use `override:` instead"。
- 第二版考虑：要么把 Go 的解释器逐函数翻译（3k 行，纯计算，没有并发），要么引入 `jaq`（Rust 的 jq 实现）后做语义适配。**不建议引入完整 jq**：yq 与 jq 的路径语义不同，适配层可能比翻译还大。

这条已登记到 11 的风险表。

## 7. 规则更新的传播

Go 的 `rules/provider` 在规则集更新后通过 `utils.Callback[P.RuleProvider]` 通知隧道重建规则列表（`ruleUpdateCallback`）。Rust 版：

```rust
// 快照里的 RuleProvider 是 Arc；更新时替换其内部数据并 bump version，
// 然后请求 Tunnel 重新编译受影响的规则。
provider.store(new_strategy);
tunnel.request_rule_rebuild(provider.name()).await;
```

重建的粒度：**整表重建**（与 Go 一致），因为规则列表很短、重建是毫秒级。不要做增量更新，那会引入"某条规则引用了旧 provider 版本"的不一致。

## 8. 排序与去重

Go 在解析 provider 时用 `seen` map 去重（同名的 proxy 只保留第一个）。Rust 版同样处理，并保留**插入顺序**（`indexmap::IndexMap`），因为 API 的 `/providers/proxies` 返回顺序会影响面板展示，且 `select` 组的默认选项顺序依赖它。
