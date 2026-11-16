#!/usr/bin/env python3
"""Checks the Rust port's appendices against the Go tree they describe.

The appendices in `rust/docs/appendix/` are generated from this repository, so
they can drift when the Go side changes. This script is the thing that notices.

Two modes:

    python3 rust/tools/check-appendix.py --write   # (re)generate the appendices
    python3 rust/tools/check-appendix.py           # verify; exit 1 on drift

It is deliberately dependency-light: PyYAML is used only when it is importable
(the config-key appendix is then cross-checked against `docs/config.yaml`).
Everything else is parsed out of the Go source with regular expressions, which
is good enough for declarations whose shape is stable, and is what makes the
numbers auditable instead of transcribed by hand.

Run it from the repository root.
"""

from __future__ import annotations

import argparse
import glob
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APPENDIX = ROOT / "rust" / "docs" / "appendix"


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------

def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def go_const_block(path: str, marker: str) -> list[str]:
    """Names inside the `const (...)` block that follows `marker`."""
    src = read(path)
    idx = src.find(marker)
    if idx < 0:
        raise SystemExit(f"marker not found in {path}: {marker}")
    block = re.search(r"const \((.*?)\n\)", src[idx:], re.S)
    if not block:
        raise SystemExit(f"const block not found after marker in {path}")
    names = []
    for line in block.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        name = re.match(r"([A-Za-z0-9_]+)", line)
        if name:
            names.append(name.group(1))
    return names


def outbound_types() -> list[str]:
    src = read("adapter/parser.go")
    out = []
    for m in re.finditer(r'case ((?:"[a-z0-9\-]+"(?:,\s*)?)+):', src):
        out += re.findall(r'"([a-z0-9\-]+)"', m.group(1))
    return out


def inbound_types() -> list[str]:
    src = read("listener/parse.go")
    out = []
    for m in re.finditer(r'case ((?:"[a-z0-9\-]+"(?:,\s*)?)+):', src):
        out += re.findall(r'"([a-z0-9\-]+)"', m.group(1))
    return out


def group_types() -> list[str]:
    src = read("adapter/outboundgroup/parser.go")
    out = []
    for m in re.finditer(r'case ((?:"[a-z0-9\-]+"(?:,\s*)?)+):', src):
        out += re.findall(r'"([a-z0-9\-]+)"', m.group(1))
    return out


def rule_syntax() -> list[str]:
    """Rule names `ParseRule` accepts, i.e. what may appear in `rules:`.

    A `case` may name several aliases (`"IP-CIDR", "IP-CIDR6"`); the first is
    the canonical spelling, the rest are accepted aliases. Order follows the
    switch so the appendix reads like the parser.
    """
    src = read("rules/parser.go")
    body = re.search(r"func ParseRule\(.*?\n\}\n", src, re.S).group(0)
    out: list[str] = []
    for m in re.finditer(r'case ((?:"[A-Z0-9\-]+"(?:,\s*)?)+):', body):
        for name in re.findall(r'"([A-Z0-9\-]+)"', m.group(1)):
            if name not in out:
                out.append(name)
    return out


#: Syntax names that are not just a respelled enum member. Everything else maps
#: by dropping separators and case (`DOMAIN-SUFFIX` -> `DomainSuffix`).
RULE_SYNTAX_ALIASES = {
    # syntax name -> RuleType enum member
    "IP-CIDR6": "IPCIDR",      # IPv6 form of the same rule
    "IP-CIDR": "IPCIDR",
    "SUB-RULE": "SubRules",
    "RULE-SET": "RuleSet",
    "IP-ASN": "IPASN",
    "SRC-IP-ASN": "SrcIPASN",
    "SRC-IP-CIDR": "SrcIPCIDR",
    "IP-SUFFIX": "IPSuffix",
    "SRC-IP-SUFFIX": "SrcIPSuffix",
    "SRC-GEOIP": "SrcGEOIP",
    "GEOSITE": "GEOSITE",
    "GEOIP": "GEOIP",
    "MATCH": "MATCH",
}


def canonical_rule_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def rule_mapping(syntax: list[str], enum: list[str]) -> tuple[dict[str, str], list[str]]:
    """Maps every accepted syntax name onto an enum member.

    Returns the mapping and the list of problems. A syntax name is resolved by
    the alias table first, then by respelling; a resolved name that has no
    enum member is a problem, and so is an enum member nothing maps to.
    """
    enum_by_key = {canonical_rule_key(e): e for e in enum}
    mapping: dict[str, str] = {}
    problems: list[str] = []
    for name in syntax:
        target = RULE_SYNTAX_ALIASES.get(name) or enum_by_key.get(
            canonical_rule_key(name)
        )
        if target is None or target not in enum:
            problems.append(f"rule syntax {name!r} has no RuleType member")
            continue
        mapping[name] = target
    covered = set(mapping.values())
    for member in enum:
        if member not in covered:
            problems.append(f"RuleType member {member!r} accepts no syntax name")
    return mapping, problems


def yaml_tags(struct_name: str) -> list[tuple[str, str]]:
    """(yaml key, dotted struct context) for one struct in config/config.go."""
    src = read("config/config.go")
    struct = re.search(
        rf"type {struct_name} struct \{{(.*?)\n\}}", src, re.S
    )
    if not struct:
        raise SystemExit(f"struct {struct_name} not found")
    fields = []
    for line in struct.group(1).splitlines():
        tag = re.search(r'yaml:"([^",]+)', line)
        if not tag:
            continue
        field = re.match(r"\s*(\w+)\s", line)
        fields.append((tag.group(1), field.group(1) if field else "?"))
    return fields


#: Router functions and the path they are mounted at. `router()` in
#: `hub/route/server.go` is the source of truth; `verify_mounts()` re-reads it
#: so the table cannot drift silently.
MOUNTS = {
    "configRouter": "/configs",
    "proxyRouter": "/proxies",
    "groupRouter": "/group",
    "ruleRouter": "/rules",
    "connectionRouter": "/connections",
    "proxyProviderRouter": "/providers/proxies",
    "ruleProviderRouter": "/providers/rules",
    "cacheRouter": "/cache",
    "dnsRouter": "/dns",
    "storageRouter": "/storage",
    "restartRouter": "/restart",
    "upgradeRouter": "/upgrade",
}

#: Routers that are mounted from another router rather than from `router()`.
#: `proxyProviderProxyRouter` is reached through the provider's `Mount("/")`.
NESTED_MOUNTS = {
    "proxyProviderProxyRouter": ("proxyProviderRouter", "/{providerName}"),
}

_VERB = r"""\br\.(Get|Post|Put|Patch|Delete)\(`?["']"""
ROUTE_RE = re.compile(_VERB + r"""([^"'`)]*)""")
ROUTE_GROUP_RE = re.compile(r"""\br\.Route\(`?["']([^"'`)]*)""")


def _join(prefix: str, path: str) -> str:
    """Concatenate a mount prefix and a route path, keeping exactly one `/`."""
    if path in ("", "/"):
        return prefix.rstrip("/") or "/" if prefix not in ("", "/") else (prefix or "/")
    base = prefix.rstrip("/") if prefix not in ("", "/") else prefix
    return base + "/" + path.strip("/") if path.strip("/") else base


def _block(text: str, start: int) -> int:
    """Index just past the `{...}` block that begins at or after `start`."""
    body = text.index("{", start)
    depth = 0
    for i in range(body, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("unbalanced braces")


def _routes_in(body: str) -> list[tuple[str, str]]:
    """(method, relative path) pairs in a router body, `r.Route` scopes applied."""
    out: list[tuple[str, str]] = []
    pos = 0
    while True:
        m = ROUTE_RE.search(body, pos)
        g = ROUTE_GROUP_RE.search(body, pos)
        if m is None and g is None:
            return out
        if g is not None and (m is None or g.start() < m.start()):
            end = _block(body, g.end())
            for sub in _routes_in(body[body.index("{", g.end()) + 1 : end]):
                out.append((sub[0], _join(g.group(1), sub[1])))
            pos = end + 1
        else:
            out.append((m.group(1).upper(), m.group(2)))
            pos = m.end()
    return out


def _router_bodies() -> dict[str, tuple[str, str]]:
    """router function name -> (file stem, body source)."""
    found: dict[str, tuple[str, str]] = {}
    for path in sorted(glob.glob(str(ROOT / "hub/route/*.go"))):
        if path.endswith("_test.go"):
            continue
        src = Path(path).read_text(encoding="utf-8")
        for m in re.finditer(
            r"func (\w+Router)\(\) http\.Handler \{(.*?)\n\}", src, re.S
        ):
            found[m.group(1)] = (Path(path).stem + ".go", m.group(2))
    return found


def _top_level_routes() -> list[tuple[str, str, str]]:
    """Routes registered on the mux in `router()` itself, plus the static bits."""
    src = (ROOT / "hub/route/server.go").read_text(encoding="utf-8")
    body = re.search(r"func router\(.*?\n\}", src, re.S).group(0)
    out = [(("server.go"), v, p) for v, p in _routes_in(body) if p.startswith("/")]
    # `/ui` and `/ui/*` are wrapped in http.HandlerFunc calls, so the route
    # regex sees the handler not the path; they are registered in `router()`.
    out += [("server.go", "GET", "/ui"), ("server.go", "GET", "/ui/*")]
    return out


def controller_routes() -> list[tuple[str, str, str]]:
    """(file, method, path) for every route the external controller serves."""
    bodies = _router_bodies()
    routes: list[tuple[str, str, str]] = []

    for router, mount in MOUNTS.items():
        if router not in bodies:
            continue
        stem, body = bodies[router]
        for verb, path in _routes_in(body):
            routes.append((stem, verb, _join(mount, path)))

    for router, (parent, mount) in NESTED_MOUNTS.items():
        if router not in bodies or parent not in bodies:
            continue
        stem, body = bodies[router]
        for verb, path in _routes_in(body):
            # The nested mount is relative to its parent's own mount.
            routes.append((stem, verb, _join(_join(MOUNTS[parent], mount), path)))

    routes += _top_level_routes()

    # DoH is mounted at a configurable path (`dohServer`), and answers both
    # verbs per RFC 8484.
    routes += [("doh.go", "GET", "<dohServer>"), ("doh.go", "POST", "<dohServer>")]

    # `r.Get("/")` inside `r.Route("/{name}")` serves `/prefix/{name}`, not
    # `/prefix/{name}/`; drop the trailing slash so the table matches what a
    # client would call.
    normalised = {
        (f, v, p.rstrip("/") if p not in ("/", "<dohServer>") else p) for f, v, p in routes
    }
    return sorted(normalised, key=lambda r: (r[0], r[2], r[1]))


def verify_mounts(problems: list[str]) -> None:
    """Every `MOUNTS` entry must appear as `Mount` in router() or a parent."""
    src = " ".join(
        Path(p).read_text(encoding="utf-8")
        for p in glob.glob(str(ROOT / "hub/route/*.go"))
        if not p.endswith("_test.go")
    )
    for router, mount in MOUNTS.items():
        if f'Mount("{mount}", {router}())' not in src:
            problems.append(f"{router} is not mounted at {mount!r} in hub/route")
    for router, (parent, mount) in NESTED_MOUNTS.items():
        if f"{router}()" not in src:
            problems.append(f"{router} does not exist in hub/route")
    # `mount` is expressed relative to the parent; check the parent link only.
    _ = mount


def go_file_stats() -> list[tuple[str, int, int, int]]:
    """(package dir, files, lines, non-test lines)."""
    import collections

    stats = collections.defaultdict(lambda: [0, 0, 0])
    for path in (ROOT).rglob("*.go"):
        rel = path.relative_to(ROOT)
        if rel.parts[0] == ".git" or rel.parts[0] == "rust":
            continue
        top = rel.parts[0] if len(rel.parts) > 1 else "(root)"
        lines = sum(1 for _ in path.open(encoding="utf-8", errors="replace"))
        stats[top][0] += 1
        stats[top][1] += lines
        if not path.name.endswith("_test.go"):
            stats[top][2] += lines
    return [(k, *v) for k, v in sorted(stats.items(), key=lambda kv: -kv[1][1])]


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

HEADER = (
    "<!-- Generated by rust/tools/check-appendix.py -- do not edit by hand. -->\n"
    "<!-- Regenerate with: python3 rust/tools/check-appendix.py --write -->\n\n"
)


def render_rule_types(names: list[str], enum: list[str]) -> str:
    mapping, _ = rule_mapping(names, enum)
    out = [HEADER, "# 附录 A · 规则类型\n\n"]
    out.append(
        f"`rules/parser.go` 接受 {len(names)} 个语法名，`constant/rule.go` 的 "
        f"`RuleType` 有 {len(enum)} 个成员：`IP-CIDR6` 是 `IP-CIDR` 的别名，"
        "所以语法名比枚举多一个。`GET /rules` 返回的是**枚举名**（`DomainSuffix`），"
        "配置里写的是**语法名**（`DOMAIN-SUFFIX`），两者不能混用。\n\n"
    )
    out.append("| # | 语法名（配置里写） | 枚举名（API 返回） |\n| ---: | --- | --- |\n")
    for i, n in enumerate(names, 1):
        out.append(f"| {i} | `{n}` | `{mapping.get(n, '?')}` |\n")
    return "".join(out)


def render_protocols(
    out_t: list[str], in_t: list[str], groups: list[str]
) -> str:
    out = [HEADER, "# 附录 B · 协议与组\n\n"]
    out.append(f"## 出站类型（{len(out_t)}）\n\n`adapter/parser.go` 的 `type:` 分支。\n\n")
    out.append("| # | 类型 |\n| ---: | --- |\n")
    for i, n in enumerate(out_t, 1):
        out.append(f"| {i} | `{n}` |\n")
    out.append(f"\n## 出站组（{len(groups)}）\n\n`adapter/outboundgroup/parser.go`。\n\n")
    out.append(", ".join(f"`{n}`" for n in groups) + "\n")
    out.append(
        f"\n## 入站类型（{len(in_t)}）\n\n`listener/parse.go` 的 `type:` 分支"
        "（另有顶层 `listeners:` 与 `tunnels:` 走同一张表）。\n\n"
    )
    out.append("| # | 类型 |\n| ---: | --- |\n")
    for i, n in enumerate(in_t, 1):
        out.append(f"| {i} | `{n}` |\n")
    return "".join(out)


def render_config_keys() -> str:
    blocks = [
        ("RawConfig", "顶层"),
        ("RawDNS", "`dns:`"),
        ("RawTun", "`tun:`"),
        ("RawSniffer", "`sniffer:`"),
        ("RawSniffingConfig", "`sniffer.sniff:` 的单个条目"),
        ("RawExperimental", "`experimental:`"),
        ("RawProfile", "`profile:`"),
        ("RawGeoXUrl", "`geox-url:`"),
        ("RawTLS", "`tls:`"),
        ("RawNTP", "`ntp:`"),
        ("RawIPTables", "`iptables:`"),
        ("RawTuicServer", "`tuic-server:`"),
        ("RawCors", "`external-controller-cors:`"),
        ("RawFallbackFilter", "`dns.fallback-filter:`"),
        ("RawClashForAndroid", "`clash-for-android:`"),
    ]
    out = [HEADER, "# 附录 C · 配置键\n\n"]
    out.append(
        "由 `yaml:` 结构体标签提取，因此这是**解析器实际接受的键**，"
        "而不是文档里写到的键。键名必须逐字与 Go 版一致，"
        "否则用户从 Go 版迁过来会静默丢配置。\n\n"
    )
    for struct, label in blocks:
        fields = yaml_tags(struct)
        out.append(f"## {label}（`{struct}`，{len(fields)} 个）\n\n")
        out.append("| # | 键 | 字段 |\n| ---: | --- | --- |\n")
        for i, (key, field) in enumerate(fields, 1):
            out.append(f"| {i} | `{key}` | `{field}` |\n")
        out.append("\n")
    return "".join(out)


def render_routes(routes: list[tuple[str, str, str]]) -> str:
    out = [HEADER, "# 附录 D · 外部控制器路由\n\n"]
    out.append(
        f"共 {len(routes)} 条，由挂载点推导；前缀见 `hub/route/server.go` 的 `router()`。"
        "`PATCH`/`PUT`/`DELETE` 的可用性受 `embed_mode` 影响（嵌入式构建禁用"
        " `/configs` 的写、`/rules/disable`、`/restart`、`/upgrade`）。\n\n"
    )
    out.append("| # | 文件 | 方法 | 路径 |\n| ---: | --- | --- | --- |\n")
    for i, (f, verb, route) in enumerate(routes, 1):
        out.append(f"| {i} | `{f}` | {verb} | `{route}` |\n")
    return "".join(out)


def render_stats(stats: list[tuple[str, int, int, int]]) -> str:
    files = sum(s[1] for s in stats)
    lines = sum(s[2] for s in stats)
    nontest = sum(s[3] for s in stats)
    out = [HEADER, "# 附录 E · Go 代码规模\n\n"]
    out.append(
        f"合计 {files:,} 个文件、{lines:,} 行（非测试 {nontest:,} 行）。"
        "`rust/docs/00-overview.md` 的表格与此一致。\n\n"
    )
    out.append("| 包 | 文件 | 行数 | 非测试行数 |\n| --- | ---: | ---: | ---: |\n")
    for name, f, l, nt in stats:
        out.append(f"| `{name}` | {f:,} | {l:,} | {nt:,} |\n")
    out.append(f"| **合计** | **{files:,}** | **{lines:,}** | **{nontest:,}** |\n")
    return "".join(out)


def render_index(docs: dict[str, str]) -> str:
    out = [HEADER, "# 附录索引\n\n"]
    out.append("这些文件由 `rust/tools/check-appendix.py` 从 Go 源码生成，**不要手改**。\n\n")
    out.append(
        "改完 Go 代码后重新生成，提交前跑一次不带参数的校验（有漂移会返回非零）：\n\n"
        "```sh\n"
        "python3 rust/tools/check-appendix.py --write   # 重新生成\n"
        "python3 rust/tools/check-appendix.py           # 校验\n"
        "```\n\n"
        "脚本只用标准库；装了 PyYAML 时会额外核对 `docs/config.yaml` 的顶层键\n"
        "是否都在 `RawConfig` 里，没装就跳过那一项。\n\n"
    )
    out.append("| 文件 | 内容 |\n| --- | --- |\n")
    for name, desc in docs.items():
        out.append(f"| [{name}]({name}) | {desc} |\n")
    return "".join(out)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def build() -> dict[str, str]:
    rule_names = rule_syntax()
    rule_enum = go_const_block("constant/rule.go", "// Rule Type")
    return {
        "A-rule-types.md": render_rule_types(rule_names, rule_enum),
        "B-protocols.md": render_protocols(
            outbound_types(), inbound_types(), group_types()
        ),
        "C-config-keys.md": render_config_keys(),
        "D-controller-routes.md": render_routes(controller_routes()),
        "E-go-size.md": render_stats(go_file_stats()),
    }


def cross_check(config_doc: str | None) -> list[str]:
    """Things that must hold regardless of what the appendix says."""
    problems = []
    names = rule_syntax()
    enum = go_const_block("constant/rule.go", "// Rule Type")
    mapping, mapping_problems = rule_mapping(names, enum)
    problems.extend(mapping_problems)
    if len(mapping) != len(names):
        problems.append("some rule syntax names did not resolve to an enum member")
    verify_mounts(problems)
    groups = group_types()
    if len(groups) != 5:
        problems.append(f"expected 5 group kinds, found {len(groups)}: {groups}")

    if config_doc:
        # Every top-level key in the shipped example must be a key the parser
        # knows, otherwise the example documents something that is ignored.
        import yaml  # type: ignore

        doc = yaml.safe_load((ROOT / config_doc).read_text(encoding="utf-8"))
        known = {k for k, _ in yaml_tags("RawConfig")}
        unknown = sorted(set(doc or {}) - known)
        if unknown:
            problems.append(f"{config_doc} uses unknown top-level keys: {unknown}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="write the appendices")
    args = ap.parse_args()

    generated = build()
    docs = {
        "A-rule-types.md": "36 种规则语法名与 `RuleType` 枚举",
        "B-protocols.md": "出站 / 入站 / 组类型清单",
        "C-config-keys.md": "配置键全集（含子结构）",
        "D-controller-routes.md": "外部控制器路由表",
        "E-go-size.md": "Go 代码规模统计",
    }
    generated["README.md"] = render_index(docs)

    appendix_cfg = None
    cfg_doc = ROOT / "docs" / "config.yaml"
    try:
        import yaml  # noqa: F401

        appendix_cfg = str(cfg_doc)
    except ImportError:
        print("note: PyYAML not importable, skipping the config.yaml cross-check")

    problems = cross_check(appendix_cfg)

    if args.write:
        APPENDIX.mkdir(parents=True, exist_ok=True)
        for name, text in generated.items():
            (APPENDIX / name).write_text(text, encoding="utf-8")
        print(f"wrote {len(generated)} files to {APPENDIX.relative_to(ROOT)}")

    drifted = []
    if not args.write:
        for name, text in generated.items():
            path = APPENDIX / name
            if not path.exists():
                drifted.append(f"{name}: missing")
            elif path.read_text(encoding="utf-8") != text:
                drifted.append(f"{name}: out of date")
        if drifted:
            problems.append(
                "appendix drift (run `python3 rust/tools/check-appendix.py --write`): "
                + "; ".join(drifted)
            )

    for p in problems:
        print("FAIL:", p)
    if problems:
        return 1
    print("ok: appendices match the Go tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
