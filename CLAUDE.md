# CLAUDE.md — Enterprise Engineering & Architectural Rules

See [`AGENTS.md`](./AGENTS.md) for full formal specifications.

## Common Commands
```bash
# Workspace verification
cargo check --workspace
cargo test --workspace
cargo test -p gw-primitives --test mathematical_theory_tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# Single crate tests
cargo test -p gw-primitives
cargo test -p gw-memcache
cargo test -p gw-chain-traits
cargo test -p gw-db
```

## Non-Negotiable Coding Rules
1. **Rust 2024 Edition & Safe Code:** `#![forbid(unsafe_code)]` on all core logic and crypto crates.
2. **Zero Floats:** `f32`/`f64` are banned via `#![deny(clippy::float_arithmetic)]`. All money/tokens must use `alloy_primitives::U256` or `u128` (USD micros).
3. **Database ORM:** Use `Oberer-lite` (`oberer-orm` & `oberer-orm-derive`) for SQLite. Call `.unenvelope()` on query results.
4. **Three-Zone Isolation:** Zero private keys in Zone A/B. Private keys exist exclusively in Zone C Nitro Enclave.
5. **In-Memory Cache:** Zero external Redis. Use `gw-memcache` with 64 cache-line padded shards, Blake3 MAC integrity, and monotonic TTL.
6. **Mathematical Rigor:** Any new algebraic formulas must be tested in `crates/gw-primitives/tests/mathematical_theory_tests.rs`.
7. **Task Tracking:** Always update `tasks.md` as progress is made.
