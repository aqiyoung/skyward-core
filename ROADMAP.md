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

- [x] Shadowsocks AEAD — AES-128/256-GCM, ChaCha20/XChaCha20-Poly1305
  (`src/adapter/shadowsocks.rs`). Plugins and 2022 ciphers remain out of scope.
- [x] VLESS over optional TLS — UUID request header, response handshake
  (`src/adapter/vless.rs`). XTLS/REALITY flows and UDP remain out of scope.
- [x] VMess AEAD — AES-128-GCM / ChaCha20-Poly1305, nested-HMAC KDF, encrypted
  header/body (`src/adapter/vmess.rs`). Legacy auth, UDP, WS/H2 wrappers remain out.
- [x] Trojan over TLS — SHA-224 auth header, SNI override (`sni`)
- [x] HTTP proxy outbound — CONNECT + optional Basic auth, optional TLS
- [x] SOCKS5 proxy outbound — RFC 1928 + optional user/pass, optional TLS
- [x] Snell v1–v3 — Argon2 KDF, shadowaead framing, CONNECT header/reply
  (`src/adapter/snell.rs`). v4/v6 record layers and UDP remain out of scope.
- [x] ShadowsocksR stream-cipher subset — MD5 KDF, AES-CFB/RC4-MD5/ChaCha20,
  origin protocol + plain obfs (`src/adapter/ssr.rs`). auth_* protocols and
  http/tls obfs remain out of scope.
- [ ] Hysteria / Hysteria2, TUIC — UDP-capable transports
- [ ] WireGuard / AmneziaWG (`adapter/outbound/wireguard`)

Prerequisites: crypto dependencies (`chacha20poly1305`, `aes-gcm`, `md-5`, `ring`
or `rustls`), a `TLS` connector abstraction, and a UUID/TLV codec layer.

## Phase 2 — rule completeness

- [x] GEOIP / GEOSITE via mihomo's protobuf `geoip.dat` / `geosite.dat`
  (self-contained decoder in `src/geo`), including `GEOIP,lan`
- [x] More rule types: `DOMAIN-REGEX`, `DOMAIN-WILDCARD`, `IP-SUFFIX`, `DST-PORT`
- [x] RULE-SET providers — file/inline/http(s), yaml/text payloads, three
  behaviors (`src/rules/provider.rs`). MRS binary format and periodic refresh
  are not implemented yet.
- [ ] MRS provider format, periodic refresh and ETag
- [ ] MMDB fallback for `GEOIP` when `.dat` files are absent
- [ ] PROCESS-NAME / PROCESS-PATH, ASN and source-address rules (need metadata)
- [ ] Logic rules (`AND`/`OR`/`NOT`), `SUB-RULE`, `REMATCH-NAME`

## Phase 3 — DNS parity

- [ ] DoH / DoT upstreams
- [ ] fake-ip and redir-host modes
- [ ] DNS hijack / sniffing (TLS ALPN, HTTP Host)

## Phase 4 — groups and providers

- [x] Proxy providers — file/inline/http(s) subscriptions, proxy filtering,
  initial HTTP health checks with latency (`src/adapter/provider.rs`)
- [x] Group `use:` entries expand to provider nodes; nodes ordered by latency
- [ ] Periodic provider refresh, ETag, `override`, persistent selections
- [ ] `relay` group, full fallback semantics

## Phase 5 — network stack

- [x] Linux transparent proxy inbounds — REDIRECT (`SO_ORIGINAL_DST`) and
  TPROXY (`IP_TRANSPARENT`) TCP, feeding the existing tunnel
  (`src/inbound/transparent.rs`). Firewall rules are operator-managed.
- [ ] TUN inbound (system + smoltcp userspace stack)
- [ ] UDP full-cone NAT for all UDP-capable protocols
- [ ] Interface binding, routing marks, dialer options
- [ ] Automatic iptables/nftables rule management

## Phase 7 — FFI & application integration

- [x] C ABI cdylib — create/apply_config/start/close/test_config/query_dns/
  set_hooks/destroy, panic-safe entries, `(ptr,len)` strings, Tokio runtime per
  handle (`src/ffi.rs`). TUN packet injection returns NotImplemented.
- [ ] gomobile `invokeMethod` bridge for the Flutter App (`src/mobile.rs`):
  [x] JSON protocol + stateless/lifecycle methods + `skyward_invoke_method` FFI;
  [x] JNI `Mobile` class + callbacks (`src/jni.rs`, `jni/java/`) — all 16 native
      methods Core.kt calls, ResultHandler/TunHandler, event delivery;
  [ ] remaining ~45 `invokeMethod` methods; [ ] wire real traffic/connections
  [ ] TUN (smoltcp) required before the App can fully run on the Rust core.

## Phase 6 — controller & operations

- [x] `/connections` live listing and WebSocket `/traffic` stream (1 Hz)
- [ ] Full REST API parity (45 routes, config GET/PUT, `/logs`, DoH, `/ui`)
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
