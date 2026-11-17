# skyward-core — Rust rewrite

This branch contains **only the Rust implementation** of the skyward proxy kernel.
The original Go kernel lives on the [`skyward`](https://github.com/aqiyoung/skyward-core/tree/skyward)
branch and is intentionally not present here.

## Start here

- [`README.rust.md`](README.rust.md) — implementation status, how to run the binary,
  REST API and the Go-package → Rust-module map.
- [`README-RUST.md`](README-RUST.md) → [`rust/README.md`](rust/README.md) — the
  separate design/migration study (12-crate architecture, M0–M7 plan, generated
  appendices). Written before code existed; the actual implementation is at the
  repository root in [`src/`](src/).
- [`ROADMAP.md`](ROADMAP.md) — porting progress.

## Layout

```
Cargo.toml / Cargo.lock     Rust crate and locked dependencies (rlib + cdylib)
src/                         kernel implementation (config, inbound, rules,
                             dns, adapters, tunnel, REST hub, C FFI)
config.example.yaml          mihomo-compatible example configuration
rust/docs/                   design and migration documents
rust/tools/                  appendix verification script
.github/workflows/           GitHub Actions: builds and tests run here
```

## Builds

Nothing is built locally. Pushes to this branch trigger
[`.github/workflows/rust-core.yaml`](.github/workflows/rust-core.yaml), which runs
tests, a locked release build, and an end-to-end smoke test
([`scripts/smoke.sh`](scripts/smoke.sh): real curl traffic through the SOCKS5 and
HTTP inbounds plus REST endpoint checks) on a GitHub runner, then uploads the
binary as an artifact.
