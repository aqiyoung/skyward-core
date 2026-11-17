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
  (CONNECT + absolute-form with origin-form rewrite), mixed port auto-detection,
  and Linux transparent proxy (`redir-port` via `SO_ORIGINAL_DST`, `tproxy-port`
  via `IP_TRANSPARENT`).
- **Rules** (`src/rules`): `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`,
  `DOMAIN-REGEX`, `DOMAIN-WILDCARD`, `IP-CIDR`/`IP-CIDR6`, `IP-SUFFIX`,
  `DST-PORT`, `GEOIP` (incl. `lan`), `GEOSITE`, `RULE-SET`, `MATCH`, with
  `no-resolve`. Rule providers (`src/rules/provider.rs`) support file/inline/http(s)
  vehicles, yaml/text payloads and the domain/ipcidr/classical behaviors.
- **Geodata** (`src/geo`): self-contained protobuf decoder for mihomo's
  `geoip.dat` / `geosite.dat`, loaded from the config directory.
- **DNS** (`src/dns`): cached async forward resolver used for IP-CIDR/GEOIP matching.
- **Adapters** (`src/adapter`): `Outbound` trait. `DIRECT` and `REJECT` terminate
  connections; `Shadowsocks` AEAD terminates via `src/adapter/shadowsocks.rs`
  (AES-128/256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305; MD5 EVP-BytesToKey,
  HKDF-SHA1 subkey, SOCKS5 target header, chunked AEAD framing), and `Trojan`
  over TLS (SHA-224 password hash, CRLF header, SNI override via `sni`), and
  `VLESS` (UUID request header, optional `tls`, SNI via `sni`/`server-name`),
  and `VMess` AEAD (`aes-128-gcm` / `chacha20-poly1305`, nested-HMAC KDF,
  AuthID, encrypted header and body chunks), `Snell` v1–v3 (Argon2 KDF,
  shadowaead framing, CONNECT header + reply), `ShadowsocksR` v1 stream-cipher
  subset (MD5 KDF, AES-CFB/RC4-MD5/ChaCha20, origin protocol + plain obfs),
  plus `http` (CONNECT with optional
  Basic auth) and `socks5` (RFC 1928 with optional user/pass) outbounds, both
  with optional TLS. Proxy groups:
  `select`, `load-balance`, `url-test`/`fallback` (TCP-connect latency probe,
  cached 60 s), plus synthetic `GLOBAL`. Proxy providers (`src/adapter/provider.rs`)
  load subscriptions from file/inline/http(s), filter nodes and run initial
  HTTP health checks; group `use:` entries expand to provider nodes ordered by
  latency.
- **Tunnel** (`src/tunnel`): mode dispatch (`rule`/`direct`/`global`), rule lookup,
  outbound resolution, bidirectional relay with upload/download counters.
- **JNI bridge** (`src/jni` + `jni/java/`): hand-written replacement for the
  gomobile-generated `com.follow.clash.core.mobile.Mobile` class. Implements all
  16 native methods `Core.kt` calls, plus `ResultHandler`/`TunHandler` callbacks
  and event delivery from native threads. TUN returns `false` (smoltcp pending).
- **Mobile protocol** (`src/mobile`): gomobile-compatible `invokeMethod` JSON
  protocol (`MethodCall`/`MethodResponse`), with stateless/lifecycle methods
  implemented (`coreVersion`, `getIsInit`, `initClash`, `shutdown`, …) and a
  structured `not_implemented` error for the rest. Exposed via
  `skyward_invoke_method` for the App's JNI bridge.
- **FFI** (`src/ffi`): C ABI (`cdylib`) with `skyward_create` / `apply_config` /
  `start_inbound` / `close_inbound` / `test_config` / `query_dns` / `set_hooks` /
  `destroy`. Every entry point catches panics; strings are `(ptr, len)`; the
  handle owns a Tokio runtime. TUN packet injection returns `NotImplemented`.
- **Hub** (`src/hub`): REST controller with optional bearer/token auth, `/connections`
  listing backed by a live connection registry, and a WebSocket `/traffic` stream
  (delta + cumulative bytes, 1 Hz) implemented with a minimal RFC 6455 server.

### REST endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/` | landing page |
| GET | `/version` | version, core name, current mode |
| GET | `/configs` | config summary and counts |
| GET | `/proxies` | outbound/group snapshot, including group selections |
| GET | `/rules` | active rules |
| GET | `/providers/rule` | loaded rule providers and entry counts |
| GET | `/providers/proxies` | loaded proxy providers, node counts and alive counts |
| GET | `/traffic` | cumulative `{up, down}` bytes |
| GET/WS | `/traffic` | WebSocket: 1 Hz `{up, down, upTotal, downTotal}` |
| GET | `/connections` | live connections (`{"connections": [...]}`) |
| DELETE | `/connections` | (reserved) close connections |
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
| `listener/redir`, `listener/tproxy` | `src/inbound/transparent.rs` | implemented (Linux) |
| `rules/` | `src/rules` | subset implemented |
| `component/dns` | `src/dns` | simplified resolver |
| `component/geodata/`, `rules/common/{geoip,geosite}.go` | `src/geo` | implemented (protobuf subset) |
| `adapter/`, `adapter/outboundgroup/` | `src/adapter` | DIRECT/REJECT + groups |
| `adapter/outbound/shadowsocks.go`, `transport/shadowsocks/shadowaead/` | `src/adapter/shadowsocks.rs` | implemented (AEAD subset) |
| `adapter/outbound/shadowsocksr.go`, `transport/ssr/` | `src/adapter/ssr.rs` | implemented (stream-cipher subset) |
| `adapter/outbound/trojan.go`, `transport/trojan/` | `src/adapter/trojan.rs`, `src/adapter/tls.rs` | implemented (TCP over TLS subset) |
| `adapter/outbound/vless.go`, `transport/vless/` | `src/adapter/vless.rs` | implemented (TCP, no XTLS/REALITY) |
| `adapter/outbound/vmess.go`, `transport/vmess/` | `src/adapter/vmess.rs` | implemented (AEAD TCP subset) |
| `tunnel/` | `src/tunnel` | implemented |
| `hub/`, `hub/executor/` | `src/hub`, `src/lib.rs` | REST + reload |
| `common/` | `src/common` | implemented |
| `transport/`, `adapter/outbound/*` | — | not ported (see ROADMAP) |
| `listener/tun/` | — | not ported |

## Transparent proxy setup (Linux)

The listeners recover the original destination but **do not install firewall
rules**. Run the core as root (or with `CAP_NET_ADMIN` / `CAP_NET_RAW`), then set
up the rules yourself, for example:

```bash
# REDIRECT (redir-port 7895)
iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-ports 7895

# TPROXY (tproxy-port 7896)
iptables -t mangle -A PREROUTING -p tcp -j TPROXY \
  --on-port 7896 --tproxy-mark 0x1/0x1
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

## Known limitations

- Beyond Shadowsocks AEAD, Trojan, VLESS, VMess, Snell (v1–v3), ShadowsocksR
  (stream-cipher subset), HTTP and SOCKS5, other `proxies` entries are parsed and
  listed in `/proxies`, but selecting one returns a clear "not implemented" error.
  Shadowsocks plugins/2022 ciphers, SSR auth protocols (auth_sha1_v4, auth_aes128_*,
  auth_chain_*) and obfs variants (http_simple, tls1.2_ticket_auth), Trojan
  WebSocket/obfs, VLESS XTLS/REALITY, Snell v4/v6, and legacy VMess are not supported.
- TLS uses webpki-roots; `skip-cert-verify` and client certificates are not supported.
- Transparent proxy is Linux/IPv4 only; the kernel does not install iptables/nftables
  rules automatically, and there is no UDP NAT or TUN/smoltcp stack yet.
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
