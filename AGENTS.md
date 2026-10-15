# AGENTS.md — Enterprise Engineering & Architectural Rules

This document specifies the non-negotiable coding standards, architectural invariants, mathematical models, and development rules for `gateway-crypto` (Unified Rust Cryptocurrency Payment Gateway, In-Memory State Engine & Treasury Custody System).

---

## 1. Toolchain, Compiler Mandates & Lints

1. **Rust Edition:** Rust 2024 (`rustc 1.85+`).
2. **Safety Invariant:** `#![forbid(unsafe_code)]` is strictly mandated across all core engine and business crates (`gw-primitives`, `gw-memcache`, `gw-chain-traits`, `gw-engine`, `gw-treasury`, `gw-kms-enclave`).
3. **Workspace Lints:** All crates must satisfy the workspace lints:
   ```toml
   [workspace.lints.rust]
   unsafe_code = "forbid"
   missing_docs = "warn"
   unused_must_use = "deny"

   [workspace.lints.clippy]
   float_arithmetic = "deny"
   cast_possible_truncation = "deny"
   cast_sign_loss = "deny"
   unwrap_used = "deny"
   expect_used = "warn"
   indexing_slicing = "deny"
   ```
4. **Unit Tests:** In test modules (`#[cfg(test)] mod tests` or integration tests in `tests/`), annotate with `#[allow(clippy::unwrap_used, clippy::expect_used)]` or return `Result`.
5. **Clean Builds:** `cargo clippy --all-targets -- -D warnings` and `cargo test --workspace` must pass with **0 errors and 0 warnings** prior to committing.

---

## 2. Mathematical Precision & Fixed-Point Arithmetic

1. **Zero Floating-Point Types:** Floating-point operations (`f32`, `f64`) are forbidden across the codebase. All token units, USD micro-valuations, basis points, and FIFO cost-basis accounting must use `alloy_primitives::U256` or `u128`.
2. **Canonical 18-Decimal Homomorphism ($\mathcal{N}_{18}$):**
   $$\mathcal{N}_{18}(r, d) = \begin{cases} r \otimes 10^{18 - d} & \text{if } d \le 18 \\ \lfloor r / 10^{d - 18} \rfloor & \text{if } d > 18 \end{cases}$$
   Balances of the same logical asset on different chains (e.g. 6-dec USDT vs 18-dec USDT) must be normalized via `to_canonical_18()` prior to cross-network aggregation.
3. **Clean 18-Decimal Dust Truncation ($\mathcal{T}_{\text{clean}}$):**
   $$R_{\text{expected}} = \mathcal{T}_{\text{clean}}(R_{\text{exact}}, 18) = \lfloor R_{\text{exact}} / 10^{12} \rfloor \otimes 10^{12}$$
   On 18-decimal assets, bottom 12 digits must be zeroed so checkout customers receive a clean 6-decimal figure.
4. **Tron 1-Sun Dust Keeper:**
   Retain 1 raw unit ($10^{-6}\text{ USDT}$) on TRON TRC-20 sweeps ($V_{\text{sweep}} = B_{\text{current}} - 1$). This preserves the SSTORE warm slot and saves $65,000\text{ Energy}$ ($\approx 50\%$) on future checkouts.
5. **Dual-Oracle Deviation Guard:**
   WebSocket mid-price vs on-chain oracle deviation must not exceed $150\text{ bps}$ ($1.5\%$). Conservative minimum price $\min(P_{\text{cex}}, P_{\text{chain}})$ must be selected. Divergence $> 150\text{ bps}$ must trip the circuit breaker and purge cached rates.
6. **Zero-Dust Hot-Wallet Split:**
   $$Q_{\to \text{Cold}} = \left\lfloor \frac{B \otimes \alpha_{\text{cold}}}{10,000} \right\rfloor, \qquad Q_{\to \text{Market}} = B - Q_{\to \text{Cold}}$$
   Ensures $Q_{\to \text{Cold}} + Q_{\to \text{Market}} \equiv B$ with zero integer truncation loss.

---

## 3. Three-Zone Zero-Trust Security Partitioning

1. **Zone A (Public Plane):** `gw-api`, `gw-memcache`, `gw-engine`, `gw-treasury`, `gw-db`.
   - **Axiom 1:** ZERO private keys or signing SDKs exist in Zone A memory or dependency trees.
   - Operates exclusively on extended public keys (`xpub`/`zpub`), CREATE2 bytecode parameters, and reference keys.
2. **Zone B (Private Node Plane):** Ingress-isolated full verification nodes (`bitcoind`, `reth`, `solana-validator`, `java-tron`, `ton-lite-server`, `sui-node`).
3. **Zone C (Air-Gapped Enclave Plane):** `gw-kms-enclave` inside AWS Nitro Enclaves / HSM / MPC.
   - `PreSignPolicyGuard` independently deserializes raw transaction payloads (PSBT, RLP, SVM Message, TON BOC, Sui BCS) and verifies destination addresses against an immutable whitelist.
   - Private key material is derived inside `zeroize::Zeroizing<[u8; 64]>` and wiped immediately on drop.

---

## 4. In-Memory State & Cache Rules (`gw-memcache`)

1. **Zero External Redis/Memcached:** Replaced by sovereign in-memory 64-shard engine (`IMPRCE`).
2. **Anti-HashDoS Sharding:** Ephemeral per-boot CSPRNG keys route keys to shards using keyed Blake3.
3. **False-Sharing Elimination:** Shards are 128-byte cache-line aligned (`#[repr(align(128))]`).
4. **Memory Hygiene:** Every cached entry implements `SecureCacheValue` and `ZeroizeOnDrop`.
5. **Blake3 MAC Integrity:** Every entry carries a 32-byte keyed MAC verified in constant time (`subtle::ConstantTimeEq`).
6. **Double-Buffered Watchlist:** Block indexers query lock-free `SnapshotMap` in sub-20ns backed by authoritative MAC-verified cache.
7. **Monotonic Clocks:** TTL calculations must strictly use monotonic `Instant` (immune to NTP rollback).

---

## 5. Database ORM Rules (`gw-db` via `Oberer-lite`)

1. **SQLite as Relational Ledger:** All relational database operations use `Oberer-lite` (`oberer-orm` and `oberer-orm-derive`) directly from `https://github.com/Kurisuma/Oberer-lite.git`.
2. **Structs are the Schema:** Tables are declared via `#[derive(OrmTable)]` on plain Rust structs in `crates/gw-db/src/models.rs`.
3. **Error Handling:** Use `.unenvelope()` from `use oberer_orm::OrmResultExt` to unwrap `OrmOk<T>` into standard `Result<T, OrmError>`.
4. **Sub-10ms Cold-Start Hydration:** On node startup, `DatabaseManager::hydrate_watchlist` must populate active checkout invoices into `InProcessWatchlistEngine` in under 10ms.

---

## 6. Typestate Lifecycle & Reorg Resilience (`gw-engine`)

1. **Compile-Time Typestate:** Invoices progress through `Invoice<Pending>` $\to$ `Invoice<Detected>` $\to$ `Invoice<VerifiedComplete>`. Invalid transitions must fail to compile.
2. **5-Gate Verification:** Every incoming transfer event must pass:
   - Gate 1: Execution success (`execution_succeeded == true`).
   - Gate 2: Signed asset and contract whitelist match.
   - Gate 3: Cumulative slippage within BPS tolerance ($R_{\text{rec}} \ge R_{\min}$).
   - Gate 4: Temporal quote validity (block timestamp $\le$ expiry).
   - Gate 5: Confirmation depth and unbroken parent-hash continuity.
3. **Reorg Rollback:** Sliding window ring buffer detects fork LCA and reverts orphaned `Detected` invoices back to `Pending` without double-credits.

---

## 7. Development & Task Management Workflow

1. **Checklist Tracking:** Maintain and update [`tasks.md`](./tasks.md) as each implementation phase or component is completed.
2. **Mathematical Verification:** Any new algebraic formula, queueing model, or fee threshold must have a corresponding test in `crates/gw-primitives/tests/mathematical_theory_tests.rs`.
3. **VCS Hygiene:** Keep commits atomic, well-described, and pushed to `https://github.com/Kurisuma/gateway-crypto`.

---

## 8. Mandatory Phase Completion Audit Protocol (Theory, Tests & Math Gate)

Before marking any implementation phase as completed (`[x]`) in [`tasks.md`](./tasks.md), the following 4-part **Mathematical Theory, Invariant & Test Audit** MUST be performed and verified:

1. **Mathematical Theory Cross-Reference:**
   - Audit all implemented functions, formulas, and state-transitions against their corresponding formal equations in `UNIFIED_RUST_CRYPTO_GATEWAY_AND_TREASURY_SPEC_THEORY.md` and `ENTERPRISE_IN_MEMORY_CACHE_SPEC_THEORY.md`.
   - Ensure zero informal or heuristic shortcuts: all calculations must strictly mirror the theoretical proofs (e.g. Erlang-B bounds, homomorphism preservation $\mathcal{N}_{18}$, FIFO prefix sums $\delta_k$, 5-Gate Boolean logic).

2. **Dedicated Mathematical Tests:**
   - Every theoretical theorem or equation relevant to the phase must have an explicit automated test in `crates/gw-primitives/tests/mathematical_theory_tests.rs` or the crate's test suite.
   - Run both deterministic boundary test cases (e.g., exact $150\text{ bps}$ vs. $151\text{ bps}$ circuit breaker) and property-based fuzz tests via `proptest`.

3. **Compiler Lints & Invariant Audits:**
   - Verify `#![forbid(unsafe_code)]` compliance.
   - Run `cargo clippy --workspace --all-targets -- -D warnings` and verify **0 errors and 0 warnings**.
   - Verify that `f32`/`f64` usage remains 0 across all touched code.

4. **Audit Documentation:**
   - Record the mathematical audit findings, verified theorems, and test outputs directly in [`tasks.md`](./tasks.md) under the phase's **Mathematical Theory & Invariants Audit Gate** checklist item.

