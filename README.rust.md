# skyward-core — Rust rewrite (branch `rust-core`)

This branch starts the incremental Rust rewrite of the mihomo-derived Go kernel in this
repository. The original Go implementation is kept intact alongside it as a reference.

## Scope — read this first

The Go kernel is ~174,000 lines across ~1,000 files (9+ proxy protocols, DNS, rule
engine, TUN stack, REST API). A faithful 1:1 port is a multi-month team effort and is
**not** what this branch claims to be.

What this branch delivers is a **compiling, runnable vertical slice** plus an
architecture that mirrors the Go kernel, so the remaining subsystems can be ported
incrementally without rework:

```
SOCKS5 / HTTP inbound  ->  rule match  ->  outbound selection  ->  DIRECT / REJECT
                                                              ->  bidirectional relay
                                                                  + traffic counters
Config (YAML)  +  DNS resolver  +  REST controller / hot reload
```

## Builds run on GitHub

This branch is built entirely by [`.github/workflows/rust-core.yaml`](.github/workflows/rust-core.yaml):
a push to `rust-core` runs `cargo test --locked --all-targets`, a locked release
build, and a CLI smoke test on a GitHub runner, then uploads the binary as the
`skyward-core-rust-linux-amd64` artifact. No local build is required.

The workflow is also manually dispatchable from the Actions tab.

## Running the binary

Download the artifact from a successful workflow run, then:

```bash
./skyward-core -c config.example.yaml -t   # validate config
./skyward-core -c config.example.yaml      # run
```

CLI flags mirror the Go binary where practical:

| Flag | Meaning |
| --- | --- |
| `-c, --config <FILE>` | YAML configuration file |
| `-d, --home <DIR>` | configuration directory |
| `-t, --test` | validate config and exit |
| `-v, --version` | print version |
| `-h, --help` | print help |
| `--socks-port`, `--http-port`, `--mixed-port` | override inbound ports |
| `--external-controller <ADDR>` | override REST controller bind address |

`RUST_LOG` overrides the log filter; otherwise `log-level` from the config is used.

## Implemented

- **Config** (`src/config`): mihomo-style YAML — `port`, `socks-port`, `mixed-port`,
  `allow-lan`, `mode`, `log-level`, `external-controller`, `secret`, `proxies`,
  `proxy-groups`, `rules`, `dns`. Validates mode and duplicate names.
- **Inbound** (`src/inbound`): SOCKS5 (IPv4/IPv6/domain, CONNECT), HTTP proxy
  (CONNECT + absolute-form with origin-form rewrite), mixed port auto-detection.
- **Rules** (`src/rules`): `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `IP-CIDR`,
  `MATCH`, with `no-resolve` modifier.
- **DNS** (`src/dns`): cached async forward resolver used for IP-CIDR matching.
- **Adapters** (`src/adapter`): `Outbound` trait; `DIRECT` and `REJECT` terminate
  connections. Proxy groups: `select`, `load-balance`, `url-test`/`fallback`
  (TCP-connect latency probe, cached 60 s), plus synthetic `GLOBAL`.
- **Tunnel** (`src/tunnel`): mode dispatch (`rule`/`direct`/`global`), rule lookup,
  outbound resolution, bidirectional relay with upload/download counters.
- **Hub** (`src/hub`): REST controller with optional bearer/token auth.

### REST endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/` | landing page |
| GET | `/version` | version, core name, current mode |
| GET | `/configs` | config summary and counts |
| GET | `/proxies` | outbound/group snapshot, including group selections |
| GET | `/rules` | active rules |
| GET | `/traffic` | cumulative `{up, down}` bytes |
| PUT | `/mode?name=<rule\|direct\|global>` | switch mode |
| PUT | `/proxies/<group>?name=<member>` | select a group member |
| PUT | `/configs` | reload config from disk (same as SIGHUP) |

Authentication: set `secret` in the config and send `Authorization: Bearer <secret>`
or `?token=<secret>`.

## Architecture map

| Go package | Rust module | Status |
| --- | --- | --- |
| `main.go` | `src/main.rs` | implemented (subset of flags) |
| `config/` | `src/config` | implemented (subset of keys) |
| `listener/` (socks, http, mixed) | `src/inbound` | implemented |
| `rules/` | `src/rules` | subset implemented |
| `component/dns` | `src/dns` | simplified resolver |
| `adapter/`, `adapter/outboundgroup/` | `src/adapter` | DIRECT/REJECT + groups |
| `tunnel/` | `src/tunnel` | implemented |
| `hub/`, `hub/executor/` | `src/hub`, `src/lib.rs` | REST + reload |
| `common/` | `src/common` | implemented |
| `transport/`, `adapter/outbound/*` | — | not ported (see ROADMAP) |
| `listener/tun/` | — | not ported |

## Known limitations

- Only `DIRECT` and `REJECT` actually connect. Other `proxies` entries are parsed and
  listed in `/proxies`, but selecting one returns a clear "not implemented" error.
- No TUN/TPROXY, no GEOIP/GEOSITE, no process-name rules, no rule providers.
- DNS uses the system forward resolver with a 60 s cache — no DoH/DoT or fake-ip.
- The REST controller does not implement the full mihomo API (no WebSocket traffic
  stream, no connections endpoint, no config write-back).

See [ROADMAP.md](ROADMAP.md) for the porting plan.

## Testing

`cargo test` covers config parsing regressions (kebab-case keys, duplicate names),
rule parsing (including `no-resolve`), and IP-CIDR matching. The data path was also
verified manually with curl through both SOCKS5 and HTTP inbounds against a local
server, plus `/traffic`, `/mode`, `/proxies/<group>` and `/configs` reload.
