# Rust core porting roadmap

The Go kernel is the reference implementation on branch `skyward`. This document
tracks the incremental Rust port on branch `rust-core`.

## Phase 0 — foundation (done in `rust-core`)

- [x] Cargo binary + library workspace; mirrors Go package boundaries
- [x] YAML config (kebab-case keys), validation, CLI overrides, SIGHUP reload
- [x] SOCKS5 / HTTP / mixed inbounds
- [x] Rule engine subset + cached DNS resolver
- [x] Outbound trait, DIRECT / REJECT, select / load-balance / url-test groups
- [x] Tunnel relay + traffic counters
- [x] REST controller subset + unit tests + end-to-end verification

## Phase 1 — real proxy protocols

Each protocol becomes an `Outbound` implementation in `src/adapter/`, keyed by
`type` in the config. Current placeholders are in `UnimplementedOutbound`.

- [ ] Shadowsocks (AEAD ciphers) — `transport/ss` equivalent
- [ ] VLESS / VMess (XTLS/REALITY later) — `transport/vless`, `transport/vmess`
- [ ] Trojan, Snell
- [ ] Hysteria / Hysteria2, TUIC — UDP-capable transports
- [ ] WireGuard / AmneziaWG (`adapter/outbound/wireguard`)

Prerequisites: crypto dependencies (`chacha20poly1305`, `aes-gcm`, `md-5`, `ring`
or `rustls`), a `TLS` connector abstraction, and a UUID/TLV codec layer.

## Phase 2 — rule completeness

- [ ] RULE-SET providers and remote provider updates
- [ ] GEOIP / GEOSITE (MMDB reader — `maxminddb` crate)
- [ ] PROCESS-NAME / PROCESS-PATH (platform-specific)
- [ ] Domain sets, ASN rules, rule `no-resolve` semantics parity

## Phase 3 — DNS parity

- [ ] DoH / DoT upstreams
- [ ] fake-ip and redir-host modes
- [ ] DNS hijack / sniffing (TLS ALPN, HTTP Host)

## Phase 4 — network stack

- [ ] TUN inbound (system + gvisor-like userspace stack)
- [ ] TPROXY / REDIR (Linux netfilter), `iptables` integration
- [ ] UDP full-cone NAT for all UDP-capable protocols
- [ ] Interface binding, routing marks, dialer options

## Phase 5 — controller & operations

- [ ] Full REST API parity (connections, WebSocket traffic stream, config PUT)
- [ ] Geo data auto-update, rule/provider health checks
- [ ] TLS for the external controller, unix socket / named pipe listeners
- [ ] `convert-ruleset`, `generate`, `age` subcommands

## Guiding constraints

- Preserve mihomo config compatibility; do not invent new keys without need.
- Keep the `Outbound` / `Inbound` trait boundaries so protocols can be added
  independently.
- Every phase should land with `cargo test` green and a manual curl-based smoke
  test where a data path exists.
- Nothing is built on the host: fmt/test/release all run in GitHub Actions via
  `.github/workflows/rust-core.yaml`, and the binary is kept as an artifact.
