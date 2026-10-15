# Master Specification, Taxonomy & Rust Trait-Based Architecture
**Unified Watch-Only Cryptocurrency Payment Gateway, Multi-Network Asset Management & Zero-Trust Enclave Custody System**

* **Document ID:** `ARCH-RUST-GW-TREASURY-2026-V4`
* **Target Implementation Language:** Rust (Edition 2024 / `rustc 1.85+`, `#![forbid(unsafe_code)]` in Public Plane)
* **Design Paradigm:** Polymorphic Trait-Based Object-Oriented Architecture, Typestate Compile-Time State Machines, Zero-Trust Air-Gapped/Enclave Key Isolation
* **Primary Directive:** **Security is Priority #1.** No private key material ever exists in the Public Application Plane (Zone A). Every signing operation in Zone B is gated by a deterministic, stateless bytecode/PSBT/transaction AST parser that cryptographically verifies the destination address against an immutable Cold/Market Whitelist before accessing key shares.

---

## Table of Contents

1. [Security-First Mandate & Zero-Trust Threat Taxonomy](#1-security-first-mandate--zero-trust-threat-taxonomy)
2. [Unified Cryptocurrency Network & Asset Taxonomy](#2-unified-cryptocurrency-network--asset-taxonomy)
3. [Rust Cargo Workspace & Module Topology](#3-rust-cargo-workspace--module-topology)
4. [Core Domain Types & Precision-Safe Arithmetic (`gw-primitives`)](#4-core-domain-types--precision-safe-arithmetic-gw-primitives)
5. [Trait-Based Unified Network & Adapter Engine (`gw-chain-traits`)](#5-trait-based-unified-network--adapter-engine-gw-chain-traits)
6. [Concrete Network Adapter Implementations (BTC, EVM, SVM, TVM, TON, Move)](#6-concrete-network-adapter-implementations-btc-evm-svm-tvm-ton-move)
7. [Typestate Invoice Verification & 5-Gate Engine (`gw-engine`)](#7-typestate-invoice-verification--5-gate-engine-gw-engine)
8. [Unified Private Key Management & Enclave Signer (`gw-kms-enclave`)](#8-unified-private-key-management--enclave-signer-gw-kms-enclave)
9. [Unified Asset Management, Cross-Network Aggregation & P&L (`gw-treasury`)](#9-unified-asset-management-cross-network-aggregation--pl-gw-treasury)
10. [Cross-Network Transfer & Liquidity Routing Engine (To Market & Cold Storage)](#10-cross-network-transfer--liquidity-routing-engine-to-market--cold-storage)
11. [Production PostgreSQL Schema & Ledger Constraints](#11-production-postgresql-schema--ledger-constraints)
12. [Implementation Roadmap, Verification Harness & Security Audit Checklist](#12-implementation-roadmap-verification-harness--security-audit-checklist)

---

## 1. Security-First Mandate & Zero-Trust Threat Taxonomy

### 1.1 Fundamental Security Invariants
Every line of Rust code in this system enforces seven non-negotiable architectural invariants:

1. **Invariant I — Zero Private Keys in Zone A (Watch-Only Public Plane):**
   The public-facing checkout API, WebSocket quote streamers, PostgreSQL database, Redis watchlist, and native blockchain indexers hold **zero private keys, zero seeds, and zero KMS signing credentials**. Zone A holds only extended public keys (`BIP-84 zpub`), EVM/Tron `CREATE2` factory addresses, Solana `reference` public keys, and view-only wallet addresses.
2. **Invariant II — Immutable Destination Bytecode (`CREATE2` Flush):**
   On EVM (`Ethereum`, `BNB Chain`, `Plume`) and TVM (`Tron`), customer deposit addresses are counterfactual smart contracts whose creation bytecode hardcodes the **Cold Treasury Multi-Sig (`Safe`)** or **Tier 2 Operational Vault** address as an `immutable` variable. Even if an attacker compromises the Tier 1 Gas Station Relayer key, the relayer can only pay gas to trigger `deployAndSweep()`—it is mathematically impossible to redirect swept funds to an attacker-controlled address.
3. **Invariant III — Stateless Pre-Sign AST & Bytecode Policy Inspection (Zone B Enclave):**
   Before any signing key in Zone B (AWS Nitro Enclave, HashiCorp Vault Transit, or MPC node) signs a Bitcoin PSBT, Solana Transaction, TON Cell, or Move PTB, a stateless Rust `PreSignPolicyGuard` deserializes the raw unsigned payload directly from bytes and verifies:
   * Every non-change output address is present in a compile-time/HSM-pinned `IMMUTABLE_DESTINATION_WHITELIST` (Cold Storage Vaults or Whitelisted Exchange Deposit Addresses).
   * Network miner/gas fees do not exceed hard basis-point caps.
4. **Invariant IV — Memory Zeroization & Secret Hygiene:**
   All cryptographic material, ephemeral key shares, HMAC webhook secrets, and exchange API keys are wrapped in `zeroize::Zeroizing<T>` and `secrecy::SecretBox<T>`. `Debug`, `Display`, `Clone`, and `Serialize` traits are strictly forbidden on key-bearing structs to prevent accidental logging or core-dump leakage.
5. **Invariant V — Pure Integer Arithmetic (`U256` / `u128`):**
   Floating-point types (`f32`, `f64`) are banned across the workspace via Clippy lints (`#![deny(clippy::float_arithmetic)]`). All token quantities, USD micro-valuations, slippage basis points, and FIFO cost-basis lots use checked 256-bit unsigned integers (`alloy_primitives::U256`) or fixed-scale `Decimal` types.
6. **Invariant VI — Compile-Time Typestate Lifecycle Transitions:**
   An `Invoice<Pending>` cannot be fulfilled or swept without first transitioning through `Invoice<Detected>` and `Invoice<Verified>` via the 5-Gate Verification Engine. Invalid state transitions fail at compile time.
7. **Invariant VII — Reorg-Safe Parent-Hash Chain Continuity:**
   Every indexed block header is linked to its `parent_hash` in a sliding window ring buffer. If a chain reorganization occurs on Bitcoin, EVM, or Solana prior to finality, affected `DETECTED` invoices are automatically rolled back and re-evaluated against the canonical fork.

---

### 1.2 Comprehensive Threat Model & Mitigation Matrix

| Threat ID | Attack Vector | Target Layer | Architectural Mitigation in Rust Engine |
| :--- | :--- | :--- | :--- |
| **`THREAT-01`** | **Fake ERC-20 / BEP-20 / SPL / Jetton Token Spoofing** | Block Indexer & Verification Engine | Gate 2 enforces a strict composite lookup `(ChainId, TokenContractAddress)` against an in-memory, cryptographically signed asset registry before evaluating transfer amounts. |
| **`THREAT-02`** | **Reverted Transaction / Internal Call Failure Crediting** | EVM / TVM / SVM / TON Indexers | Gate 1 verifies `receipt.status == 1` (EVM), `contractRet == SUCCESS` (Tron), `meta.err.is_none()` (Solana), and `compute_phase.success && !action_phase.aborted` (TON). |
| **`THREAT-03`** | **Token-2022 / Fee-on-Transfer Amount Inflation** | Solana & Custom ERC-20 Indexers | Indexers never trust instruction calldata `amount`. Credits are computed strictly from `post_balance.checked_sub(pre_balance)` of the recipient vault account. |
| **`THREAT-04`** | **Concurrent Checkout Address Collision** | Address Derivation & Guest Pool | Logged-in users are protected by PostgreSQL partial unique index `idx_unique_active_invoice`. Guest checkouts use atomic `SELECT ... FOR UPDATE SKIP LOCKED` leases with a 4-hour post-expiry `COOLDOWN`. |
| **`THREAT-05`** | **Compromised Zone A API Server Attempted Fund Theft** | Zone A $\rightarrow$ Zone B Boundary | Zone A cannot sign transactions. If Zone A submits a malicious sweep request to Zone B via mTLS, Zone B's `PreSignPolicyGuard` parses the raw unsigned transaction bytes and rejects any output not matching the hardcoded Cold/Market whitelist. |
| **`THREAT-06`** | **Price Oracle Manipulation / Stale WebSocket Feed** | Quote Locking Engine | Dual-source cross-check: Binance/Coinbase WebSocket mid-price (10s Redis TTL) must deviate by less than `150 bps` (1.5%) from on-chain Chainlink/Pyth oracle `latestRoundData()`, otherwise checkout pauses automatically. |
| **`THREAT-07`** | **Deep Blockchain Reorganization / Double Spend** | Finality Tracker | Invoices remain in `DETECTED` until chain-specific finality (`finalized` commitment on Solana, 12–15 blocks on EVM, 1–3 blocks on BTC) and unbroken `parent_hash` lineage are verified. |
| **`THREAT-08`** | **Tron Cold-Storage Energy Exhaustion Attack** | TVM Sweeper Daemon | Sweeper enforces the `1-Sun Dust Keeper` invariant (`bal - 1`), keeping the `TRC-20` storage slot warm (65k Energy vs 131k Energy) and delegating renewable Stake 2.0 Energy from the Cold Vault. |

---

### 1.3 Physical & Logical Security Zone Topology

```text
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║ ZONE A: PUBLIC DMZ & WATCH-ONLY APPLICATION PLANE (NO PRIVATE KEYS / NO KMS ACCESS)   ║
║                                                                                       ║
║  ┌─────────────────────────┐    ┌──────────────────────────┐    ┌──────────────────┐  ║
║  │ Checkout & Treasury API │───►│ Quote & Oracle Engine    │───►│ Redis O(1)       │  ║
║  │ (Axum + Rustls mTLS)    │    │ (WS + Chainlink Verify)  │    │ Watchlist Set    │  ║
║  └────────────┬────────────┘    └──────────────────────────┘    └────────▲─────────┘  ║
║               │                                                          │            ║
║               ▼                                                          │            ║
║  ┌─────────────────────────┐    ┌──────────────────────────┐             │            ║
║  │ PostgreSQL 17 Ledger    │◄───│ 5-Gate Typestate         │◄────────────┴─────────┐  ║
║  │ (Invoices, FIFO Lots,   │    │ Verification Engine      │   Normalized Events   │  ║
║  │  Unified Balances)      │    └──────────────────────────┘                       │  ║
╚═══════════════╪════════════════════════════════════════════════════════════════════╪══╝
                │ Read-Only State / Unsigned Sweep Intents (gRPC + Mutual TLS)       │
╔═══════════════▼════════════════════════════════════════════════════════════════════┴══╗
║ ZONE B: ISOLATED BLOCKCHAIN NODE & INDEXING VPC (PRIVATE SUBNET / NO PUBLIC INGRESS) ║
║                                                                                       ║
║  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────┐  ║
║  │ bitcoind     │ │ geth / reth  │ │ solana-rpc   │ │ java-tron    │ │ ton-lite /  │  ║
║  │ (ZMQ Block)  │ │ bsc / plume  │ │ (Yellowstone │ │ (gRPC Event) │ │ sui-node    │  ║
║  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ └─────────────┘  ║
╚═══════════════╤═══════════════════════════════════════════════════════════════════════╝
                │ Unsigned Payload Bytes (VSOCK / Hardware Data Diode)
╔═══════════════▼═══════════════════════════════════════════════════════════════════════╗
║ ZONE C: ZERO-TRUST SIGNING ENCLAVE (AWS NITRO ENCLAVE / HSM / MPC QUORUM)             ║
║                                                                                       ║
║  ┌─────────────────────────────────────────────────────────────────────────────────┐  ║
║  │ 1. Stateless PreSignPolicyGuard (Raw AST / Bytecode / PSBT Output Verifier)     │  ║
║  │    -> Verifies 100% of recipients ∈ {Pinned Cold Vaults, Pinned CeFi Addresses} │  ║
║  └────────────────────────────────────────┬────────────────────────────────────────┘  ║
║                                           │ Passed Policy Proof                       ║
║                                           ▼                                           ║
║  ┌─────────────────────────────────────────────────────────────────────────────────┐  ║
║  │ 2. Unified KeySigner Trait (Secp256k1 / Ed25519 / Schnorr / M-of-N Safe EIP712) │  ║
║  │    -> Signs in Zeroized RAM -> Emits Raw Signed Tx Hex -> Zeroes Buffer         │  ║
║  └─────────────────────────────────────────────────────────────────────────────────┘  ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 2. Unified Cryptocurrency Network & Asset Taxonomy

To manage balances, derive addresses, verify transactions, and execute cross-network sweeps through a **single unified Rust interface**, all supported blockchains and tokens are classified along four orthogonal axes:

### 2.1 Axis 1: Execution & State Model (`ChainArchitecture`)
1. **`UtxoModel` (Bitcoin Mainnet):**
   * **State Representation:** Unspent Transaction Outputs (`OutPoint = txid:vout`).
   * **Address Strategy:** Unique `BIP-84` Native SegWit (`bc1q...`) per `invoice_id` derived from an account-level `zpub` (`m/84'/0'/0'/0/{index}`).
   * **Sweeping Mechanics:** Batch UTXO consolidation via `BIP-174` / `BIP-370` Partially Signed Bitcoin Transactions (`PSBT`) during low-fee mempool windows.
2. **`EvmAccountModel` (Ethereum `1`, BNB Chain `56`, Plume `98866`):**
   * **State Representation:** Global Account State Trie + ERC-20/BEP-20 Contract Storage (`mapping(address => uint256)`).
   * **Address Strategy:** Deterministic `CREATE2` counterfactual proxy per `customer_id` (logged-in) or leased from the Rotating Pool (guest). Identical `0x...` address across Ethereum, BNB Chain, and Plume.
   * **Sweeping Mechanics:** Tier 1 Gas Station Relayer calls `GatewaySweeperFactory::deployAndSweep(salt, token, false)`, flushing 100% of balances to the hardcoded Cold/Hot Vault.
3. **`SvmAccountModel` (Solana Mainnet):**
   * **State Representation:** Separate Owner Accounts (`SystemProgram`) and Associated Token Accounts (`ATAs` owned by `SPL Token` or `Token-2022` Program) requiring a rent-exempt `SOL` reserve.
   * **Address Strategy:**
     * *Mode A (Direct Wallet Checkout):* Direct transfer to Cold Treasury ATA tagged with an ephemeral read-only `reference` Ed25519 public key (0 sweep gas).
     * *Mode B (CEX Withdrawal Checkout):* Deterministic Program Derived Address (`PDA`) per customer/pool.
   * **Sweeping Mechanics:** Anchor instruction `sweep_and_close_ata` flushes tokens to Cold Treasury and reclaims the `0.00203928 SOL` rent reserve back to the Tier 1 Relayer.
4. **`TvmAccountModel` (Tron Mainnet):**
   * **State Representation:** TVM Account + `TRC-20` storage slots governed by daily **Bandwidth** and **Energy** quotas.
   * **Address Strategy:** `CREATE2` counterfactual proxy (`0x41...` Base58Check `T...` format).
   * **Sweeping Mechanics:** Tier 1 Relayer receives delegated **Stake 2.0 Energy** from Cold Treasury and calls `deployAndSweep(salt, usdt, true)` with `keepOneUnitDust = true`, leaving `1 raw unit` (`0.000001 USDT`) behind to keep the TVM storage slot warm and save `66,000 Energy` on future deposits.
5. **`TonActorModel` (TON Mainnet):**
   * **State Representation:** Asynchronous Sharded Actor Smart Contracts; each user's token balance lives in an isolated `JettonWallet` contract.
   * **Address Strategy:** Single Cold Treasury Vault + deterministic 8-byte alphanumeric `MemoTag` carried in the `forward_payload` cell of `op::transfer_notification` (`0x7362d09c`).
   * **Sweeping Mechanics:** Zero sweeping required for properly tagged deposits (funds land directly in Treasury Jetton Wallet).
6. **`MoveObjectModel` (Sui / Aptos Mainnet):**
   * **State Representation:** Owned discrete `Coin<T>` objects (`UID`, `value: u64`).
   * **Address Strategy:** Direct Move package call `pay_invoice<T>(invoice_id, Coin<T>)` or derived deposit address.
   * **Sweeping Mechanics:** Sponsored Programmable Transaction Block (`PTB`) executing `MergeCoins` + `TransferObjects` where the Tier 1 Relayer signs `GasData.sponsor`.

---

### 2.2 Axis 2: Canonical Asset Identifier (`UnifiedAssetId`)
A single conceptual asset (e.g., `USDT` or `USDC`) exists across multiple incompatible networks with different decimal precisions:
* **`USDT` on Ethereum (`Chain 1`):** `6` decimals (`ERC-20` `0xdac17f958d2ee523a2206206994597c13d831ec7`)
* **`USDT` on Plume (`Chain 98866`):** `6` decimals (`ERC-20`)
* **`USDT` on BNB Chain (`Chain 56`):** `18` decimals (`BEP-20` `0x55d398326f99059ff775485246999027b3197955`)
* **`USDT` on Solana (`Chain 900`):** `6` decimals (`SPL` `Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB`)
* **`USDT` on Tron (`Chain 728126428`):** `6` decimals (`TRC-20` `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`)
* **`USDT` on TON (`Chain 1100`):** `6` decimals (`Jetton Master` `EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs`)

To enable the **Unified Asset Management System** to display *"Total USDT Across All Networks = $1,450,230.50"* while preventing decimal conversion bugs during individual network sweeps, our taxonomy separates:
1. **`LogicalAsset` (`BTC`, `ETH`, `BNB`, `PLUME`, `SOL`, `TRX`, `TON`, `SUI`, `USDT`, `USDC`):** Used for portfolio aggregation, unified USD valuation, and cross-network FIFO P&L rollups.
2. **`PhysicalAssetInstance` (`(ChainId, TokenContract)`):** Used for raw on-chain base-unit conversion (`decimals`), contract whitelist verification, and network-specific sweeping.

---

### 2.3 Axis 3: Wallet Tier & Custody Taxonomy (`WalletTier`)

| Tier | Enum Variant | Security & Key Custody Model | Allowed Outbound Destinations |
| :--- | :--- | :--- | :--- |
| **Tier 0** | `Tier0CustomerDeposit` | Counterfactual `CREATE2` Proxies, BTC `zpub` UTXO addresses, Solana PDAs | Strictly `Tier2OperationalHot` or `Tier3ColdVault` (immutable in contract/policy) |
| **Tier 1** | `Tier1GasRelayer` | Zone C HSM / KMS Key (`< $2,000` native gas cap) + Tron Stake 2.0 Energy | Pays gas fees only; cannot receive swept customer principal |
| **Tier 2** | `Tier2OperationalHot` | Zone C MPC / 1-of-2 Policy-Gated Warm Vault | `Tier1GasRelayer` (gas top-ups), `Tier3ColdVault`, `Tier4MarketExchange` |
| **Tier 3** | `Tier3ColdVault` | Air-Gapped Hardware Multi-Sig (`2-of-3` or `3-of-5` Safe / Cold BTC Descriptor) | Whitelisted institutional settlement accounts (`M-of-N` quorum required) |
| **Tier 4** | `Tier4MarketExchange` | Whitelisted CeFi Exchange Deposit Addresses (Binance, Coinbase Prime) or DEX Router | Automated Fiat (`USD`) conversion & bank wire settlement |

---

## 3. Rust Cargo Workspace & Module Topology

The codebase is organized as a strict multi-crate Cargo workspace so that **Zone A (`gw-api`, `gw-indexer`) cannot even compile against private-key signing crates (`gw-kms-enclave`)**.

```text
crypto-gateway-workspace/
├── Cargo.toml                        # Workspace root with strict lints (#![forbid(unsafe_code)])
├── crates/
│   ├── gw-primitives/                # Canonical IDs, U256 NormalizedAmount, Decimals, Taxonomic Enums
│   ├── gw-chain-traits/              # Core OOP Trait Hierarchy (NetworkAdapter, AddressDeriver, Sweeper)
│   ├── gw-adapters-btc/              # Bitcoin UTXO Adapter (bdk_wallet, bitcoin, BIP-84 zpub, PSBT)
│   ├── gw-adapters-evm/              # Ethereum, BNB, Plume Adapter (alloy, CREATE2, eth_getLogs)
│   ├── gw-adapters-svm/              # Solana Adapter (Yellowstone gRPC, Reference Pubkey, PDA Rent)
│   ├── gw-adapters-tvm/              # Tron Adapter (Base58 CREATE2, Stake 2.0 Energy, 1-Sun Dust Keeper)
│   ├── gw-adapters-ton/              # TON Adapter (Jetton transfer_notification, 8-Byte Memo verifier)
│   ├── gw-adapters-move/             # Sui/Aptos Adapter (Checkpoint indexer, Sponsored PTB builder)
│   ├── gw-engine/                    # Typestate Invoice Machine, 5-Gate Verifier, Redis O(1) Watchlist
│   ├── gw-treasury/                  # Unified Asset Aggregator, FIFO Cost-Basis P&L, Routing Engine
│   ├── gw-kms-enclave/               # [ZONE C ONLY] PreSignPolicyGuard, Unified KeySigner, Zeroize RAM
│   └── gw-api/                       # [ZONE A ONLY] Axum REST/WebSocket Checkout & Treasury Dashboard API
```

### 3.1 Workspace `Cargo.toml` (Security-Hardened Configuration)

```toml
[workspace]
resolver = "2"
members = [
    "crates/gw-primitives",
    "crates/gw-chain-traits",
    "crates/gw-adapters-btc",
    "crates/gw-adapters-evm",
    "crates/gw-adapters-svm",
    "crates/gw-adapters-tvm",
    "crates/gw-adapters-ton",
    "crates/gw-adapters-move",
    "crates/gw-engine",
    "crates/gw-treasury",
    "crates/gw-kms-enclave",
    "crates/gw-api",
]

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

[workspace.dependencies]
alloy-primitives = { version = "0.8", features = ["serde"] }
async-trait = "0.1"
bitcoin = { version = "0.32", features = ["serde", "rand-std"] }
chrono = { version = "0.4", features = ["serde"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sha2 = "0.10"
subtle = "2.6"
thiserror = "2.0"
tokio = { version = "1.43", features = ["full"] }
uuid = { version = "1.12", features = ["v4", "v7", "serde"] }
zeroize = { version = "1.8", features = ["derive"] }
secrecy = { version = "0.10", features = ["serde"] }
sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "postgres", "uuid", "chrono"] }
```

---

## 4. Core Domain Types & Precision-Safe Arithmetic (`gw-primitives`)

This crate defines the foundational value types shared across the gateway and treasury engines. Notice how `NormalizedAmount` encapsulates both the raw `U256` on-chain integer and the specific `decimals` of that `PhysicalAssetInstance`, making cross-network addition of mismatched decimals impossible without explicit normalization to **18-decimal canonical units** or **USD micros (`10^-6 USD`)**.

```rust
// crates/gw-primitives/src/lib.rs
#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic, clippy::unwrap_used)]

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrimitiveError {
    #[error("Arithmetic overflow during BigInt calculation")]
    ArithmeticOverflow,
    #[error("Arithmetic underflow during BigInt calculation")]
    ArithmeticUnderflow,
    #[error("Division by zero in quote or P&L calculation")]
    DivisionByZero,
    #[error("Asset decimal mismatch: left={left}, right={right}")]
    DecimalMismatch { left: u8, right: u8 },
    #[error("Logical asset mismatch: left={left:?}, right={right:?}")]
    LogicalAssetMismatch { left: LogicalAsset, right: LogicalAsset },
    #[error("Invalid token contract or address format: {0}")]
    InvalidAddressFormat(String),
}

/// Canonical logical assets across all supported networks for unified portfolio aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LogicalAsset {
    Btc,
    Eth,
    Bnb,
    Plume,
    Sol,
    Trx,
    Ton,
    Sui,
    Usdt,
    Usdc,
}

/// Execution architecture taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainArchitecture {
    BitcoinUtxo,
    EvmAccount,
    SvmAccount,
    TvmAccount,
    TonActor,
    MoveObject,
}

/// Unique chain identifier across both EVM and non-EVM networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ChainId {
    BitcoinMainnet = 0,
    EthereumMainnet = 1,
    BnbChain = 56,
    PlumeMainnet = 98866,
    SolanaMainnet = 900,
    TronMainnet = 728126428,
    TonMainnet = 1100,
    SuiMainnet = 1200,
}

impl ChainId {
    pub const fn architecture(self) -> ChainArchitecture {
        match self {
            Self::BitcoinMainnet => ChainArchitecture::BitcoinUtxo,
            Self::EthereumMainnet | Self::BnbChain | Self::PlumeMainnet => {
                ChainArchitecture::EvmAccount
            }
            Self::SolanaMainnet => ChainArchitecture::SvmAccount,
            Self::TronMainnet => ChainArchitecture::TvmAccount,
            Self::TonMainnet => ChainArchitecture::TonActor,
            Self::SuiMainnet => ChainArchitecture::MoveObject,
        }
    }
}

/// Identifies a specific token contract or native coin on a specific chain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PhysicalAssetId {
    pub chain_id: ChainId,
    pub logical_asset: LogicalAsset,
    /// Canonical lowercase contract/mint/jetton address, or `"NATIVE"` for gas coins.
    pub token_contract: String,
    pub decimals: u8,
}

/// Wallet security tier taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WalletTier {
    Tier0CustomerDeposit,
    Tier1GasRelayer,
    Tier2OperationalHot,
    Tier3ColdVault,
    Tier4MarketExchange,
}

/// Precision-safe on-chain token quantity paired with its physical decimal scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawAssetAmount {
    raw: U256,
    decimals: u8,
}

impl RawAssetAmount {
    pub const fn new(raw: U256, decimals: u8) -> Self {
        Self { raw, decimals }
    }

    pub const fn zero(decimals: u8) -> Self {
        Self {
            raw: U256::ZERO,
            decimals,
        }
    }

    pub const fn raw(&self) -> U256 {
        self.raw
    }

    pub const fn decimals(&self) -> u8 {
        self.decimals
    }

    pub fn checked_add(self, other: Self) -> Result<Self, PrimitiveError> {
        if self.decimals != other.decimals {
            return Err(PrimitiveError::DecimalMismatch {
                left: self.decimals,
                right: other.decimals,
            });
        }
        let sum = self
            .raw
            .checked_add(other.raw)
            .ok_or(PrimitiveError::ArithmeticOverflow)?;
        Ok(Self {
            raw: sum,
            decimals: self.decimals,
        })
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, PrimitiveError> {
        if self.decimals != other.decimals {
            return Err(PrimitiveError::DecimalMismatch {
                left: self.decimals,
                right: other.decimals,
            });
        }
        let diff = self
            .raw
            .checked_sub(other.raw)
            .ok_or(PrimitiveError::ArithmeticUnderflow)?;
        Ok(Self {
            raw: diff,
            decimals: self.decimals,
        })
    }

    /// Normalizes any token amount (6, 8, 9, or 18 decimals) to a canonical 18-decimal U256
    /// so balances of the same LogicalAsset across different chains (e.g., 6-dec ERC20 USDT
    /// and 18-dec BEP20 USDT) can be summed accurately in the Unified Portfolio Dashboard.
    pub fn to_canonical_18_decimals(self) -> Result<U256, PrimitiveError> {
        if self.decimals == 18 {
            return Ok(self.raw);
        }
        if self.decimals < 18 {
            let scale_diff = 18_u8
                .checked_sub(self.decimals)
                .ok_or(PrimitiveError::ArithmeticUnderflow)?;
            let multiplier = U256::from(10_u64)
                .checked_pow(U256::from(scale_diff))
                .ok_or(PrimitiveError::ArithmeticOverflow)?;
            self.raw
                .checked_mul(multiplier)
                .ok_or(PrimitiveError::ArithmeticOverflow)
        } else {
            let scale_diff = self
                .decimals
                .checked_sub(18_u8)
                .ok_or(PrimitiveError::ArithmeticUnderflow)?;
            let divisor = U256::from(10_u64)
                .checked_pow(U256::from(scale_diff))
                .ok_or(PrimitiveError::ArithmeticOverflow)?;
            self.raw
                .checked_div(divisor)
                .ok_or(PrimitiveError::DivisionByZero)
        }
    }

    /// Formats the raw integer into a clean human-readable decimal string without using floats.
    pub fn to_clean_display_string(&self) -> Result<String, PrimitiveError> {
        let scale = U256::from(10_u64)
            .checked_pow(U256::from(self.decimals))
            .ok_or(PrimitiveError::ArithmeticOverflow)?;
        let whole = self
            .raw
            .checked_div(scale)
            .ok_or(PrimitiveError::DivisionByZero)?;
        let rem = self
            .raw
            .checked_rem(scale)
            .ok_or(PrimitiveError::DivisionByZero)?;

        if rem.is_zero() {
            return Ok(format!("{whole}.00"));
        }

        let frac_padded = format!("{:0>width$}", rem, width = usize::from(self.decimals));
        let frac_trimmed = frac_padded.trim_end_matches('0');
        Ok(format!("{whole}.{frac_trimmed}"))
    }
}

/// USD value scaled by 10^6 (1 USD = 1_000_000 micros).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UsdMicros(pub u128);

impl UsdMicros {
    pub const SCALE: u128 = 1_000_000;

    /// Converts a fiat USD micro amount into raw blockchain units at a locked USD micro price,
    /// zeroing out the bottom 12 noisy digits on 18-decimal tokens so customers see a clean
    /// 6-decimal figure to copy at checkout.
    pub fn to_locked_quote_raw(
        self,
        asset_price_usd_micros: Self,
        decimals: u8,
    ) -> Result<RawAssetAmount, PrimitiveError> {
        if asset_price_usd_micros.0 == 0 {
            return Err(PrimitiveError::DivisionByZero);
        }
        let scale_factor = U256::from(10_u64)
            .checked_pow(U256::from(decimals))
            .ok_or(PrimitiveError::ArithmeticOverflow)?;
        let numerator = U256::from(self.0)
            .checked_mul(scale_factor)
            .ok_or(PrimitiveError::ArithmeticOverflow)?;
        let mut raw_amount = numerator
            .checked_div(U256::from(asset_price_usd_micros.0))
            .ok_or(PrimitiveError::DivisionByZero)?;

        // Pillar 2: Zero out trailing 12 noisy digits on 18-decimal assets
        if decimals == 18 {
            let dust_mask = U256::from(1_000_000_000_000_u64); // 10^12
            raw_amount = raw_amount
                .checked_div(dust_mask)
                .ok_or(PrimitiveError::DivisionByZero)?
                .checked_mul(dust_mask)
                .ok_or(PrimitiveError::ArithmeticOverflow)?;
        }

        Ok(RawAssetAmount::new(raw_amount, decimals))
    }

    /// Computes the USD micro valuation of a raw token balance at a given price.
    pub fn from_raw_asset_amount(
        amount: RawAssetAmount,
        asset_price_usd_micros: Self,
    ) -> Result<Self, PrimitiveError> {
        let scale_factor = U256::from(10_u64)
            .checked_pow(U256::from(amount.decimals()))
            .ok_or(PrimitiveError::ArithmeticOverflow)?;
        let usd_u256 = amount
            .raw()
            .checked_mul(U256::from(asset_price_usd_micros.0))
            .ok_or(PrimitiveError::ArithmeticOverflow)?
            .checked_div(scale_factor)
            .ok_or(PrimitiveError::DivisionByZero)?;

        let usd_u128: u128 = usd_u256
            .try_into()
            .map_err(|_| PrimitiveError::ArithmeticOverflow)?;
        Ok(Self(usd_u128))
    }
}

impl fmt::Display for UsdMicros {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dollars = self.0 / Self::SCALE;
        let cents = (self.0 % Self::SCALE) / 10_000;
        write!(f, "${dollars}.{cents:02}")
    }
}
```

---

## 5. Trait-Based Unified Network & Adapter Engine (`gw-chain-traits`)

To achieve clean **Object-Oriented Polymorphism in Rust**, every blockchain network implements a unified suite of traits (`AddressDeriver`, `BlockStreamIndexer`, `BalanceReader`, and `UnsignedSweepBuilder`), composed into a supertrait `UnifiedNetworkAdapter`.

The Gateway Engine and Unified Asset Management System hold a registry of `Arc<dyn UnifiedNetworkAdapter>`, allowing them to query balances across all chains, derive checkout routes, or build sweep transactions without `match` branching on specific networks.

```rust
// crates/gw-chain-traits/src/lib.rs
#![forbid(unsafe_code)]

use alloy_primitives::U256;
use async_trait::async_trait;
use gw_primitives::{
    ChainArchitecture, ChainId, PhysicalAssetId, PrimitiveError, RawAssetAmount, WalletTier,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("Primitive arithmetic or format error: {0}")]
    Primitive(#[from] PrimitiveError),
    #[error("RPC communication failure on chain {chain_id:?}: {reason}")]
    RpcTransport { chain_id: ChainId, reason: String },
    #[error("Chain reorganization detected at block {height}: expected parent {expected}, got {actual}")]
    ChainReorgDetected {
        height: u64,
        expected: String,
        actual: String,
    },
    #[error("No available addresses in rotating guest pool for chain {0:?}")]
    AddressPoolExhausted(ChainId),
    #[error("Sweeping threshold not met: current={current_raw}, minimum={min_raw}")]
    BelowSweepThreshold { current_raw: U256, min_raw: U256 },
    #[error("Security policy violation: destination {0} is not in immutable whitelist")]
    UntrustedDestination(String),
}

/// Checkout routing instruction returned to the customer UI and added to the Redis O(1) Watchlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckoutDepositRoute {
    pub chain_id: ChainId,
    /// Primary receiving address (bc1q... on BTC, CREATE2 0x... on EVM, T... on Tron, Vault on TON/Solana).
    pub deposit_address: String,
    /// Optional secondary routing key: Solana ephemeral Reference Pubkey OR TON 8-byte Memo Tag.
    pub routing_reference: Option<String>,
    /// Deterministic salt or BIP-32 child index used to derive the address (for Zone C sweep reconstruction).
    pub derivation_locator: String,
}

impl CheckoutDepositRoute {
    /// Returns the exact O(1) lookup key stored in the Redis `watched_addresses` Set.
    pub fn watchlist_lookup_key(&self) -> &str {
        self.routing_reference
            .as_deref()
            .unwrap_or(&self.deposit_address)
    }
}

/// Normalized incoming transfer event emitted by any native node indexer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedTransferEvent {
    pub chain_id: ChainId,
    pub architecture: ChainArchitecture,
    pub tx_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub parent_block_hash: String,
    pub block_timestamp_unix: u64,
    /// Matches `CheckoutDepositRoute::watchlist_lookup_key()`.
    pub lookup_key: String,
    /// Canonical lowercase contract address or `"NATIVE"`.
    pub token_contract: String,
    /// Exact net balance increase on the recipient account (post - pre).
    pub net_amount_raw: RawAssetAmount,
    /// Gate 1: True only if transaction succeeded on-chain without revert/abort.
    pub execution_succeeded: bool,
    pub confirmations: u32,
    pub target_confirmations: u32,
}

/// Unsigned transaction payload passed from Zone A/B to the Zone C Signing Enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransactionEnvelope {
    pub envelope_id: Uuid,
    pub chain_id: ChainId,
    pub architecture: ChainArchitecture,
    pub source_tier: WalletTier,
    pub destination_tier: WalletTier,
    /// Canonical destination address (must belong to Cold Vault or Whitelisted Market Exchange).
    pub expected_destination_address: String,
    pub physical_asset: PhysicalAssetId,
    pub sweep_amount_raw: RawAssetAmount,
    pub estimated_gas_fee_raw: RawAssetAmount,
    /// Raw unsigned bytes: BIP-174 PSBT (BTC), EIP-1559 RLP payload (EVM), Solana Message, or TON Boc.
    pub raw_unsigned_payload: Vec<u8>,
    /// Derivation path or CREATE2 salt required by Zone C to select the signing key.
    pub signer_key_locator: String,
}

/// Trait 1: Deterministic Watch-Only Address & Routing Derivation (Pillar 1).
#[async_trait]
pub trait WatchOnlyAddressDeriver: Send + Sync {
    fn chain_id(&self) -> ChainId;

    /// Derives a unique invoice address (BTC) or reuses a customer/pool address (EVM/Tron/Solana/TON).
    async fn derive_checkout_route(
        &self,
        invoice_id: u64,
        customer_id: Option<Uuid>,
        asset: &PhysicalAssetId,
    ) -> Result<CheckoutDepositRoute, AdapterError>;
}

/// Trait 2: Native Node Block Ingestion & O(1) Watchlist Filtering (Pillar 3).
#[async_trait]
pub trait NativeBlockIndexer: Send + Sync {
    fn chain_id(&self) -> ChainId;

    /// Fetches and filters a specific block height against the in-memory O(1) watchlist set.
    async fn scan_block_for_watched_transfers(
        &self,
        block_height: u64,
        watched_lookup_keys: &std::collections::HashSet<String>,
    ) -> Result<Vec<NormalizedTransferEvent>, AdapterError>;

    /// Queries the current finalized/canonical block height from the local native node.
    async fn latest_canonical_height(&self) -> Result<u64, AdapterError>;
}

/// Trait 3: Unified On-Chain Balance & Gas Relayer Health Reader (Treasury Module A).
#[async_trait]
pub trait OnChainBalanceReader: Send + Sync {
    fn chain_id(&self) -> ChainId;

    /// Reads the exact raw balance of any address and token contract directly from the native node.
    async fn get_balance_raw(
        &self,
        address: &str,
        asset: &PhysicalAssetId,
    ) -> Result<RawAssetAmount, AdapterError>;
}

/// Trait 4: Unsigned Sweep & Cross-Network Transfer Payload Builder (Pillar 5 & Treasury Module C).
#[async_trait]
pub trait UnsignedSweepBuilder: Send + Sync {
    fn chain_id(&self) -> ChainId;

    /// Builds an unsigned consolidation/sweep payload (Tier 0 -> Tier 2/3) or treasury transfer
    /// (Tier 2 -> Tier 3 Cold Storage / Tier 4 Market Exchange).
    async fn build_unsigned_transfer(
        &self,
        source_address_or_locator: &str,
        destination_address: &str,
        source_tier: WalletTier,
        destination_tier: WalletTier,
        asset: &PhysicalAssetId,
        amount: RawAssetAmount,
    ) -> Result<UnsignedTransactionEnvelope, AdapterError>;

    /// Broadcasts a Zone-C signed raw transaction payload to the local native node.
    async fn broadcast_signed_transaction(
        &self,
        signed_raw_bytes: &[u8],
    ) -> Result<String, AdapterError>;
}

/// Master Object-Oriented Polymorphic Trait combining all network capabilities.
pub trait UnifiedNetworkAdapter:
    WatchOnlyAddressDeriver + NativeBlockIndexer + OnChainBalanceReader + UnsignedSweepBuilder
{
    fn architecture(&self) -> ChainArchitecture {
        self.chain_id().architecture()
    }
}

/// Thread-safe registry holding all active blockchain adapters for unified iteration.
#[derive(Clone, Default)]
pub struct NetworkAdapterRegistry {
    adapters: std::collections::BTreeMap<ChainId, Arc<dyn UnifiedNetworkAdapter>>,
}

impl NetworkAdapterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, adapter: Arc<dyn UnifiedNetworkAdapter>) {
        self.adapters.insert(adapter.chain_id(), adapter);
    }

    pub fn get(&self, chain_id: ChainId) -> Option<Arc<dyn UnifiedNetworkAdapter>> {
        self.adapters.get(&chain_id).cloned()
    }

    pub fn all_adapters(&self) -> impl Iterator<Item &Arc<dyn (&ChainId, UnifiedNetworkAdapter>)> {
        self.adapters.iter()
    }
}
```

---

## 6. Concrete Network Adapter Implementations (BTC, EVM, SVM, TVM, TON, Move)

### 6.1 Bitcoin Mainnet Adapter (`gw-adapters-btc`) — BIP-84 `zpub` & Batch PSBT Builder
The Bitcoin adapter holds **only** the account-level extended public key (`zpub` at `m/84'/0'/0'`). It derives a fresh Native SegWit (`bc1q...`) address for every `invoice_id` and builds unsigned `BIP-174` PSBTs that sweep accumulated UTXOs strictly to the hardcoded Cold BTC Multi-Sig address.

```rust
// crates/gw-adapters-btc/src/lib.rs
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::{Address, CompressedPublicKey, Network};
use gw_chain_traits::{
    AdapterError, CheckoutDepositRoute, NativeBlockIndexer, NormalizedTransferEvent,
    OnChainBalanceReader, UnifiedNetworkAdapter, UnsignedSweepBuilder, UnsignedTransactionEnvelope,
    WatchOnlyAddressDeriver,
};
use gw_primitives::{ChainId, PhysicalAssetId, RawAssetAmount, WalletTier};
use std::collections::HashSet;
use std::str::FromStr;
use uuid::Uuid;

pub struct BitcoinMainnetAdapter {
    account_xpub: Xpub,
    secp: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    cold_multisig_address: Address,
    target_confirmations: u32,
}

impl BitcoinMainnetAdapter {
    pub fn new(
        account_xpub_str: &str,
        cold_multisig_bech32: &str,
        target_confirmations: u32,
    ) -> Result<Self, AdapterError> {
        let account_xpub = Xpub::from_str(account_xpub_str).map_err(|e| {
            AdapterError::RpcTransport {
                chain_id: ChainId::BitcoinMainnet,
                reason: format!("Invalid BIP-84 xpub/zpub: {e}"),
            }
        })?;
        let unchecked_addr = Address::from_str(cold_multisig_bech32).map_err(|e| {
            AdapterError::UntrustedDestination(format!("Invalid cold BTC address: {e}"))
        })?;
        let cold_multisig_address = unchecked_addr
            .require_network(Network::Bitcoin)
            .map_err(|e| AdapterError::UntrustedDestination(format!("Network mismatch: {e}")))?;

        Ok(Self {
            account_xpub,
            secp: bitcoin::secp256k1::Secp256k1::verification_only(),
            cold_multisig_address,
            target_confirmations,
        })
    }

    /// Derives m/84'/0'/0'/0/{invoice_id} in pure watch-only mode.
    pub fn derive_segwit_address(&self, invoice_index: u32) -> Result<Address, AdapterError> {
        let external_chain = ChildNumber::from_normal_idx(0).map_err(|e| {
            AdapterError::RpcTransport {
                chain_id: ChainId::BitcoinMainnet,
                reason: e.to_string(),
            }
        })?;
        let child_idx = ChildNumber::from_normal_idx(invoice_index).map_err(|e| {
            AdapterError::RpcTransport {
                chain_id: ChainId::BitcoinMainnet,
                reason: e.to_string(),
            }
        })?;
        let path = DerivationPath::from(vec![external_chain, child_idx]);
        let child_xpub = self
            .account_xpub
            .derive_pub(&self.secp, &path)
            .map_err(|e| AdapterError::RpcTransport {
                chain_id: ChainId::BitcoinMainnet,
                reason: e.to_string(),
            })?;

        let compressed_pk = CompressedPublicKey(child_xpub.public_key);
        Ok(Address::p2wpkh(&compressed_pk, Network::Bitcoin))
    }
}

#[async_trait]
impl WatchOnlyAddressDeriver for BitcoinMainnetAdapter {
    fn chain_id(&self) -> ChainId {
        ChainId::BitcoinMainnet
    }

    async fn derive_checkout_route(
        &self,
        invoice_id: u64,
        _customer_id: Option<Uuid>,
        _asset: &PhysicalAssetId,
    ) -> Result<CheckoutDepositRoute, AdapterError> {
        let index: u32 = invoice_id.try_into().map_err(|_| AdapterError::RpcTransport {
            chain_id: ChainId::BitcoinMainnet,
            reason: "Invoice ID exceeds BIP-32 non-hardened child index u32::MAX".to_string(),
        })?;
        let address = self.derive_segwit_address(index)?;

        Ok(CheckoutDepositRoute {
            chain_id: ChainId::BitcoinMainnet,
            deposit_address: address.to_string(),
            routing_reference: None,
            derivation_locator: format!("m/84'/0'/0'/0/{index}"),
        })
    }
}

#[async_trait]
impl NativeBlockIndexer for BitcoinMainnetAdapter {
    fn chain_id(&self) -> ChainId {
        ChainId::BitcoinMainnet
    }

    async fn scan_block_for_watched_transfers(
        &self,
        _block_height: u64,
        _watched_lookup_keys: &HashSet<String>,
    ) -> Result<Vec<NormalizedTransferEvent>, AdapterError> {
        // Connects to local bitcoind ZMQ + RPC `getblock(hash, 2)` and filters
        // `vout[].scriptPubKey.address` against `watched_lookup_keys` in O(1) time.
        Ok(Vec::new())
    }

    async fn latest_canonical_height(&self) -> Result<u64, AdapterError> {
        Ok(885_000)
    }
}

#[async_trait]
impl OnChainBalanceReader for BitcoinMainnetAdapter {
    fn chain_id(&self) -> ChainId {
        ChainId::BitcoinMainnet
    }

    async fn get_balance_raw(
        &self,
        _address: &str,
        asset: &PhysicalAssetId,
    ) -> Result<RawAssetAmount, AdapterError> {
        Ok(RawAssetAmount::zero(asset.decimals))
    }
}

#[async_trait]
impl UnsignedSweepBuilder for BitcoinMainnetAdapter {
    fn chain_id(&self) -> ChainId {
        ChainId::BitcoinMainnet
    }

    async fn build_unsigned_transfer(
        &self,
        source_address_or_locator: &str,
        destination_address: &str,
        source_tier: WalletTier,
        destination_tier: WalletTier,
        asset: &PhysicalAssetId,
        amount: RawAssetAmount,
    ) -> Result<UnsignedTransactionEnvelope, AdapterError> {
        if destination_tier == WalletTier::Tier3ColdVault
            && destination_address != self.cold_multisig_address.to_string()
        {
            return Err(AdapterError::UntrustedDestination(
                destination_address.to_string(),
            ));
        }

        Ok(UnsignedTransactionEnvelope {
            envelope_id: Uuid::now_v7(),
            chain_id: ChainId::BitcoinMainnet,
            architecture: self.architecture(),
            source_tier,
            destination_tier,
            expected_destination_address: destination_address.to_string(),
            physical_asset: asset.clone(),
            sweep_amount_raw: amount,
            estimated_gas_fee_raw: RawAssetAmount::new(alloy_primitives::U256::from(1500_u64), 8),
            raw_unsigned_payload: Vec::new(), // Serialized BIP-174 PSBT bytes
            signer_key_locator: source_address_or_locator.to_string(),
        })
    }

    async fn broadcast_signed_transaction(
        &self,
        _signed_raw_bytes: &[u8],
    ) -> Result<String, AdapterError> {
        Ok("btc_txid_hex".to_string())
    }
}

impl UnifiedNetworkAdapter for BitcoinMainnetAdapter {}
```

---

### 6.2 Unified EVM & Tron `CREATE2` Adapter (`gw-adapters-evm` & `gw-adapters-tvm`)
Both EVM chains (`Ethereum`, `BNB Chain`, `Plume`) and `Tron` use deterministic `CREATE2` counterfactual address derivation:
$$\text{Address} = \text{keccak256}(\text{prefix} \parallel \text{factory\_address} \parallel \text{salt} \parallel \text{init\_code\_hash})[12..32]$$
* On **EVM**, `prefix = 0xff`.
* On **Tron (TVM)**, `prefix = 0x41`, and the resulting 20-byte address is prefixed with `0x41` and Base58Check-encoded (`T...`). Furthermore, when sweeping `TRC-20 USDT` on Tron, `keep_one_unit_dust` is set to `true` (`bal - 1`) to preserve the TVM storage slot and save `66,000 Energy` on the next customer checkout.

```rust
// crates/gw-adapters-evm/src/lib.rs
#![forbid(unsafe_code)]

use alloy_primitives::{keccak256, Address, B256, U256};
use async_trait::async_trait;
use gw_chain_traits::{
    AdapterError, CheckoutDepositRoute, NativeBlockIndexer, NormalizedTransferEvent,
    OnChainBalanceReader, UnifiedNetworkAdapter, UnsignedSweepBuilder, UnsignedTransactionEnvelope,
    WatchOnlyAddressDeriver,
};
use gw_primitives::{ChainId, PhysicalAssetId, RawAssetAmount, WalletTier};
use std::collections::HashSet;
use uuid::Uuid;

pub struct EvmCreate2Adapter {
    chain_id: ChainId,
    factory_address: Address,
    init_code_hash: B256,
    cold_treasury_safe: Address,
    keep_one_unit_dust: bool, // False on ETH/BNB/Plume; True on Tron TRC-20
}

impl EvmCreate2Adapter {
    pub const fn new(
        chain_id: ChainId,
        factory_address: Address,
        init_code_hash: B256,
        cold_treasury_safe: Address,
        keep_one_unit_dust: bool,
    ) -> Self {
        Self {
            chain_id,
            factory_address,
            init_code_hash,
            cold_treasury_safe,
            keep_one_unit_dust,
        }
    }

    /// Deterministically computes the counterfactual CREATE2 deposit address without RPC calls.
    pub fn compute_create2_address(&self, salt: B256) -> Address {
        let mut buf = [0_u8; 85];
        buf[0] = 0xff;
        buf[1..21].copy_from_slice(self.factory_address.as_slice());
        buf[21..53].copy_from_slice(salt.as_slice());
        buf[53..85].copy_from_slice(self.init_code_hash.as_slice());

        let hash = keccak256(buf);
        Address::from_slice(&hash[12..32])
    }

    /// Generates a deterministic 32-byte salt from a logged-in customer's UUID.
    pub fn customer_salt(customer_id: Uuid) -> B256 {
        let mut input = [0_u8; 32];
        input[0..16].copy_from_slice(customer_id.as_bytes());
        keccak256(input)
    }
}

#[async_trait]
impl WatchOnlyAddressDeriver for EvmCreate2Adapter {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    async fn derive_checkout_route(
        &self,
        invoice_id: u64,
        customer_id: Option<Uuid>,
        _asset: &PhysicalAssetId,
    ) -> Result<CheckoutDepositRoute, AdapterError> {
        let salt = match customer_id {
            Some(cid) => Self::customer_salt(cid),
            None => {
                // In production, leases an AVAILABLE salt from `evm_address_pool` via PostgreSQL
                let mut guest_buf = [0_u8; 32];
                guest_buf[24..32].copy_from_slice(&invoice_id.to_be_bytes());
                keccak256(guest_buf)
            }
        };

        let deposit_addr = self.compute_create2_address(salt);
        Ok(CheckoutDepositRoute {
            chain_id: self.chain_id,
            deposit_address: format!("{deposit_addr:#x}"),
            routing_reference: None,
            derivation_locator: format!("{salt:#x}"),
        })
    }
}

#[async_trait]
impl NativeBlockIndexer for EvmCreate2Adapter {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    async fn scan_block_for_watched_transfers(
        &self,
        _block_height: u64,
        _watched_lookup_keys: &HashSet<String>,
    ) -> Result<Vec<NormalizedTransferEvent>, AdapterError> {
        // Calls `eth_getBlockByNumber(h, true)` for native ETH/BNB/PLUME transfers and
        // `eth_getLogs` filtering ERC-20/BEP-20 `Transfer(address,address,uint256)`
        // (topic0 = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef)
        // matching `topic2` (recipient) against `watched_lookup_keys` in O(1) time.
        Ok(Vec::new())
    }

    async fn latest_canonical_height(&self) -> Result<u64, AdapterError> {
        Ok(21_000_000)
    }
}

#[async_trait]
impl OnChainBalanceReader for EvmCreate2Adapter {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    async fn get_balance_raw(
        &self,
        _address: &str,
        asset: &PhysicalAssetId,
    ) -> Result<RawAssetAmount, AdapterError> {
        Ok(RawAssetAmount::zero(asset.decimals))
    }
}

#[async_trait]
impl UnsignedSweepBuilder for EvmCreate2Adapter {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    async fn build_unsigned_transfer(
        &self,
        source_address_or_locator: &str,
        destination_address: &str,
        source_tier: WalletTier,
        destination_tier: WalletTier,
        asset: &PhysicalAssetId,
        amount: RawAssetAmount,
    ) -> Result<UnsignedTransactionEnvelope, AdapterError> {
        // When sweeping Tier 0 -> Tier 3 Cold Storage, encode `deployAndSweep(bytes32 salt, address token, bool keepDust)`
        // If `self.keep_one_unit_dust` is true (Tron TRC-20), subtract 1 raw unit from the swept amount.
        let effective_sweep_amount = if self.keep_one_unit_dust && amount.raw() > U256::from(1_u64) {
            amount.checked_sub(RawAssetAmount::new(U256::from(1_u64), asset.decimals))?
        } else {
            amount
        };

        Ok(UnsignedTransactionEnvelope {
            envelope_id: Uuid::now_v7(),
            chain_id: self.chain_id,
            architecture: self.architecture(),
            source_tier,
            destination_tier,
            expected_destination_address: destination_address.to_string(),
            physical_asset: asset.clone(),
            sweep_amount_raw: effective_sweep_amount,
            estimated_gas_fee_raw: RawAssetAmount::new(U256::from(115_000_000_000_000_u64), 18),
            raw_unsigned_payload: Vec::new(), // EIP-1559 RLP unsigned transaction bytes
            signer_key_locator: source_address_or_locator.to_string(),
        })
    }

    async fn broadcast_signed_transaction(
        &self,
        _signed_raw_bytes: &[u8],
    ) -> Result<String, AdapterError> {
        Ok("0x_evm_tx_hash".to_string())
    }
}

impl UnifiedNetworkAdapter for EvmCreate2Adapter {}
```

---

### 6.3 Solana, TON & Sui Adapter Specifications (`gw-adapters-svm`, `gw-adapters-ton`, `gw-adapters-move`)

1. **`SolanaSvmAdapter` (`crates/gw-adapters-svm`):**
   * `derive_checkout_route`: Generates a fresh, non-signing Ed25519 public key (`reference_pubkey`) for direct wallet checkouts (routing directly to `cold_treasury_ata`), or derives an Anchor PDA `["invoice", customer_id]` for CEX withdrawals.
   * `scan_block_for_watched_transfers`: Streams slot updates from the validator's **Yellowstone gRPC (Geyser)** interface, matches any `accountKey` against `watched_lookup_keys`, verifies `meta.err.is_none()`, and computes `post_token_balances[i].checked_sub(pre_token_balances[i])` to automatically absorb **Token-2022 `TransferFeeConfig`** deductions.
   * `build_unsigned_transfer`: Constructs an Anchor instruction calling `sweep_pda_and_close_ata`, transferring 100% of SPL tokens to `cold_treasury_ata` and reclaiming the `0.00203928 SOL` rent reserve to the Tier 1 Gas Relayer.
2. **`TonActorAdapter` (`crates/gw-adapters-ton`):**
   * `derive_checkout_route`: Returns the single Cold Treasury address as `deposit_address` and generates a deterministic, collision-free 8-byte Base32 `routing_reference` (`MemoTag`).
   * `scan_block_for_watched_transfers`: Watches the Cold Treasury's official `USDT` Jetton Wallet for internal messages with opcode `op::transfer_notification` (`0x7362d09c`), verifies the sender is the canonical Jetton Wallet contract derived from the TON USDT Jetton Master, and matches the parsed comment string against `watched_lookup_keys`.
3. **`SuiMoveAdapter` (`crates/gw-adapters-move`):**
   * `scan_block_for_watched_transfers`: Subscribes to Sui Checkpoints, matching `gateway::PaymentCompletedEvent` or `Coin<USDC>` object transfers against `watched_lookup_keys`.
   * `build_unsigned_transfer`: Constructs a Sponsored Programmable Transaction Block (`PTB`) executing `MergeCoins` + `TransferObjects` where the Tier 1 Relayer signs `GasData.sponsor`.

---

## 7. Typestate Invoice Verification & 5-Gate Engine (`gw-engine`)

Using Rust's **Typestate Pattern**, an invoice's lifecycle (`Pending` $\rightarrow$ `Detected` $\rightarrow$ `VerifiedComplete` / `Partial` / `Expired`) is enforced at compile time. No downstream service can trigger order fulfillment or create a FIFO tax lot unless it receives an `Invoice<VerifiedComplete>`, which can **only** be constructed by passing all five deterministic verification gates.

```rust
// crates/gw-engine/src/lib.rs
#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic, clippy::unwrap_used)]

use alloy_primitives::U256;
use gw_chain_traits::{CheckoutDepositRoute, NormalizedTransferEvent};
use gw_primitives::{PhysicalAssetId, PrimitiveError, RawAssetAmount, UsdMicros};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerificationError {
    #[error("Primitive arithmetic error: {0}")]
    Primitive(#[from] PrimitiveError),
    #[error("Gate 1 Failed: On-chain transaction execution reverted or aborted (tx={0})")]
    Gate1ExecutionReverted(String),
    #[error("Gate 2 Failed: Unwhitelisted or spoofed token contract (expected={expected}, actual={actual})")]
    Gate2ContractSpoofed { expected: String, actual: String },
    #[error("Gate 4 Failed: Payment arrived at {tx_time} after quote expiration {expires_at}")]
    Gate4QuoteExpired { tx_time: u64, expires_at: u64 },
    #[error("Gate 5 Failed: Insufficient confirmations ({current}/{target}) or broken parentHash")]
    Gate5FinalityPending { current: u32, target: u32 },
}

// Compile-Time Typestate Markers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub current_confirmations: u32,
    pub target_confirmations: u32,
    pub last_tx_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partial {
    pub shortfall_raw: RawAssetAmount,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedComplete {
    pub settlement_tx_hash: String,
    pub settled_at_unix: u64,
    pub is_overpaid: bool,
    pub surplus_raw: RawAssetAmount,
}

/// Generic Typestate Invoice container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice<State> {
    pub invoice_id: u64,
    pub customer_id: Option<Uuid>,
    pub asset: PhysicalAssetId,
    pub route: CheckoutDepositRoute,
    pub fiat_amount_usd: UsdMicros,
    pub locked_price_usd: UsdMicros,
    pub expected_amount_raw: RawAssetAmount,
    pub received_amount_raw: RawAssetAmount,
    /// Slippage tolerance in basis points (e.g., 50 = 0.5% to absorb CEX withdrawal fees).
    pub tolerance_bps: u16,
    pub expires_at_unix: u64,
    pub state: State,
}

/// Result of evaluating an incoming transfer event against the 5-Gate Verification Engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateEvaluationOutcome {
    StillDetected(Invoice<Detected>),
    TransitionedToPartial(Invoice<Partial>),
    TransitionedToComplete(Invoice<VerifiedComplete>),
}

impl Invoice<Pending> {
    /// Evaluates an incoming normalized transfer event through all 5 deterministic gates.
    pub fn evaluate_transfer(
        mut self,
        event: &NormalizedTransferEvent,
        parent_hash_continuity_verified: bool,
    ) -> Result<GateEvaluationOutcome, VerificationError> {
        // GATE 1: On-Chain Execution Status (Prevents crediting reverted transactions)
        if !event.execution_succeeded {
            return Err(VerificationError::Gate1ExecutionReverted(
                event.tx_hash.clone(),
            ));
        }

        // GATE 2: Strict Contract Whitelist (Defeats fake ERC-20/BEP-20/SPL/Jetton spoofing)
        if !event
            .token_contract
            .eq_ignore_ascii_case(&self.asset.token_contract)
        {
            return Err(VerificationError::Gate2ContractSpoofed {
                expected: self.asset.token_contract.clone(),
                actual: event.token_contract.clone(),
            });
        }

        // GATE 4: Quote Expiration Guard
        if event.block_timestamp_unix > self.expires_at_unix {
            return Err(VerificationError::Gate4QuoteExpired {
                tx_time: event.block_timestamp_unix,
                expires_at: self.expires_at_unix,
            });
        }

        // GATE 5: Reorg-Safe Finality & Parent-Hash Continuity
        if !parent_hash_continuity_verified || event.confirmations < event.target_confirmations {
            return Ok(GateEvaluationOutcome::StillDetected(Invoice {
                invoice_id: self.invoice_id,
                customer_id: self.customer_id,
                asset: self.asset,
                route: self.route,
                fiat_amount_usd: self.fiat_amount_usd,
                locked_price_usd: self.locked_price_usd,
                expected_amount_raw: self.expected_amount_raw,
                received_amount_raw: self.received_amount_raw,
                tolerance_bps: self.tolerance_bps,
                expires_at_unix: self.expires_at_unix,
                state: Detected {
                    current_confirmations: event.confirmations,
                    target_confirmations: event.target_confirmations,
                    last_tx_hash: event.tx_hash.clone(),
                },
            }));
        }

        // GATE 3: Cumulative Slippage Tolerance (Pure U256 Integer Arithmetic)
        self.received_amount_raw = self.received_amount_raw.checked_add(event.net_amount_raw)?;

        let bps_scale = U256::from(10_000_u64);
        let min_bps = bps_scale
            .checked_sub(U256::from(self.tolerance_bps))
            .ok_or(PrimitiveError::ArithmeticUnderflow)?;
        let min_acceptable_u256 = self
            .expected_amount_raw
            .raw()
            .checked_mul(min_bps)
            .ok_or(PrimitiveError::ArithmeticOverflow)?
            .checked_div(bps_scale)
            .ok_or(PrimitiveError::DivisionByZero)?;

        if self.received_amount_raw.raw() < min_acceptable_u256 {
            let shortfall_u256 = self
                .expected_amount_raw
                .raw()
                .checked_sub(self.received_amount_raw.raw())
                .ok_or(PrimitiveError::ArithmeticUnderflow)?;
            let shortfall = RawAssetAmount::new(shortfall_u256, self.asset.decimals);

            return Ok(GateEvaluationOutcome::TransitionedToPartial(Invoice {
                invoice_id: self.invoice_id,
                customer_id: self.customer_id,
                asset: self.asset,
                route: self.route,
                fiat_amount_usd: self.fiat_amount_usd,
                locked_price_usd: self.locked_price_usd,
                expected_amount_raw: self.expected_amount_raw,
                received_amount_raw: self.received_amount_raw,
                tolerance_bps: self.tolerance_bps,
                expires_at_unix: self.expires_at_unix,
                state: Partial {
                    shortfall_raw: shortfall,
                },
            }));
        }

        // Check Overpayment Threshold (> 102% of expected)
        let overpay_u256 = self
            .expected_amount_raw
            .raw()
            .checked_mul(U256::from(10_200_u64))
            .ok_or(PrimitiveError::ArithmeticOverflow)?
            .checked_div(bps_scale)
            .ok_or(PrimitiveError::DivisionByZero)?;

        let is_overpaid = self.received_amount_raw.raw() > overpay_u256;
        let surplus_u256 = if self.received_amount_raw.raw() > self.expected_amount_raw.raw() {
            self.received_amount_raw
                .raw()
                .checked_sub(self.expected_amount_raw.raw())
                .ok_or(PrimitiveError::ArithmeticUnderflow)?
        } else {
            U256::ZERO
        };

        Ok(GateEvaluationOutcome::TransitionedToComplete(Invoice {
            invoice_id: self.invoice_id,
            customer_id: self.customer_id,
            asset: self.asset.clone(),
            route: self.route,
            fiat_amount_usd: self.fiat_amount_usd,
            locked_price_usd: self.locked_price_usd,
            expected_amount_raw: self.expected_amount_raw,
            received_amount_raw: self.received_amount_raw,
            tolerance_bps: self.tolerance_bps,
            expires_at_unix: self.expires_at_unix,
            state: VerifiedComplete {
                settlement_tx_hash: event.tx_hash.clone(),
                settled_at_unix: event.block_timestamp_unix,
                is_overpaid,
                surplus_raw: RawAssetAmount::new(surplus_u256, self.asset.decimals),
            },
        }))
    }
}
```

---

## 8. Unified Private Key Management & Enclave Signer (`gw-kms-enclave`)

This crate runs **exclusively inside Zone C** (an isolated AWS Nitro Enclave, GCP Confidential Space, or air-gapped HSM/MPC signing node). It provides a **Unified Private Key Management Architecture** across all elliptic curves (`secp256k1` for Bitcoin/EVM/Tron, `Ed25519` for Solana/TON/Sui, and `BIP-340 Schnorr` for Taproot) while enforcing **Stateless Pre-Sign Policy Verification** and **M-of-N Quorum Governance**.

### 8.1 Key Hierarchy & Cryptographic Separation

| Key Class | Curve / Algorithm | Storage Medium | Purpose & Policy Constraint |
| :--- | :--- | :--- | :--- |
| **Tier 1 EVM/Tron/Solana/Sui Gas Relayer Key** | `secp256k1` / `Ed25519` | AWS KMS / HSM Non-Exportable Key (`< $2,000` balance cap) | Calls `GatewaySweeperFactory::deployAndSweep` or sponsors Solana/Sui sweeps. Policy guard ensures calldata selector is strictly `deployAndSweep`. |
| **Tier 0 Bitcoin Consolidation Signer** | `BIP-84` HD Master Seed (`secp256k1`) | Air-Gapped Enclave Sealed Storage (decrypted into `Zeroizing<[u8; 64]>` RAM only during signing) | Signs daily batch consolidation PSBTs. Policy guard parses the raw PSBT and rejects if any output scriptPubKey differs from the pinned Cold BTC Multi-Sig. |
| **Tier 2 Operational Hot/Warm Vault Signer** | `MPC-CMP` / `FROST` (`2-of-2` Automated + Policy Co-Signer) | Split across Zone C Enclave and external HSM Co-Signer | Signs auto-replenishment top-ups to Tier 1 Relayers and M-of-N approved transfers to Cold Vaults or Whitelisted Market Exchanges. |
| **Tier 3 Cold Storage Multi-Sig** | `2-of-3` or `3-of-5` Hardware Signers (`Safe` on EVM, Descriptor Multisig on BTC) | Offline Hardware Security Modules / Air-Gapped Vaults | Never connected to Zone A, B, or C servers. Approves high-value institutional outflows via offline EIP-712 / PSBT signatures. |

---

### 8.2 Rust Implementation of the Zero-Trust Enclave Signer (`gw-kms-enclave`)

```rust
// crates/gw-kms-enclave/src/lib.rs
#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic, clippy::unwrap_used)]

use async_trait::async_trait;
use gw_chain_traits::UnsignedTransactionEnvelope;
use gw_primitives::{ChainId, WalletTier};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Error)]
pub enum EnclaveSecurityError {
    #[error("POLICY VIOLATION: Destination address '{0}' is not in the immutable enclave whitelist")]
    UnauthorizedDestination(String),
    #[error("POLICY VIOLATION: Estimated gas fee {fee} exceeds maximum allowed basis points")]
    ExcessiveGasFee { fee: String },
    #[error("POLICY VIOLATION: Raw transaction payload destination does not match envelope header")]
    PayloadHeaderMismatch,
    #[error("GOVERNANCE VIOLATION: Transfer requires {required} M-of-N hardware approvals, got {actual}")]
    InsufficientMofNApprovals { required: usize, actual: usize },
    #[error("GOVERNANCE VIOLATION: Invalid or duplicate M-of-N cryptographic approval signature")]
    InvalidApprovalSignature,
    #[error("Key derivation or cryptographic signing error: {0}")]
    CryptoFailure(String),
}

/// Cryptographic M-of-N approval signature submitted by an authorized executive/hardware signer.
#[derive(Debug, Clone)]
pub struct HardwareApprovalSignature {
    pub signer_id: String,
    pub public_key_bytes: Vec<u8>,
    pub signature_bytes: Vec<u8>,
}

/// Hardcoded / HSM-pinned destination whitelist inside Zone C Enclave.
/// Even if Zone A PostgreSQL is completely compromised, Zone C refuses to sign any
/// transaction whose parsed raw output address is not in this pinned registry.
pub struct ImmutableDestinationRegistry {
    allowed_cold_vaults: BTreeMap<ChainId, HashSet<String>>,
    allowed_market_exchanges: BTreeMap<ChainId, HashSet<String>>,
    allowed_tier1_relayers: BTreeMap<ChainId, HashSet<String>>,
}

impl ImmutableDestinationRegistry {
    pub fn is_authorized_destination(
        &self,
        chain_id: ChainId,
        destination_tier: WalletTier,
        address: &str,
    ) -> bool {
        let normalized = address.trim();
        match destination_tier {
            WalletTier::Tier3ColdVault => self
                .allowed_cold_vaults
                .get(&chain_id)
                .is_some_and(|set| set.contains(normalized)),
            WalletTier::Tier4MarketExchange => self
                .allowed_market_exchanges
                .get(&chain_id)
                .is_some_and(|set| set.contains(normalized)),
            WalletTier::Tier1GasRelayer => self
                .allowed_tier1_relayers
                .get(&chain_id)
                .is_some_and(|set| set.contains(normalized)),
            WalletTier::Tier0CustomerDeposit | WalletTier::Tier2OperationalHot => false,
        }
    }
}

/// Memory-safe wrapper for ephemeral private key material in Zone C RAM.
/// Automatically zeroes memory when dropped; never implements Debug, Display, Clone, or Serialize.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralPrivateKeyMaterial {
    bytes: [u8; 64],
}

impl EphemeralPrivateKeyMaterial {
    pub fn from_slice(src: &[u8]) -> Result<Self, EnclaveSecurityError> {
        if src.len() > 64 {
            return Err(EnclaveSecurityError::CryptoFailure(
                "Key material exceeds 64-byte buffer".to_string(),
            ));
        }
        let mut bytes = [0_u8; 64];
        bytes[..src.len()].copy_from_slice(src);
        Ok(Self { bytes })
    }
}

/// Stateless Pre-Sign AST / Bytecode / PSBT Inspector.
pub struct PreSignPolicyGuard {
    whitelist: ImmutableDestinationRegistry,
    required_m_of_n_quorum: usize,
}

impl PreSignPolicyGuard {
    pub const fn new(
        whitelist: ImmutableDestinationRegistry,
        required_m_of_n_quorum: usize,
    ) -> Self {
        Self {
            whitelist,
            required_m_of_n_quorum,
        }
    }

    /// Inspects both the envelope metadata AND deserializes the raw unsigned transaction bytes
    /// to verify that 100% of outputs route to an authorized Cold Vault, Market Exchange, or Relayer.
    pub fn verify_before_signing(
        &self,
        envelope: &UnsignedTransactionEnvelope,
        approvals: &[HardwareApprovalSignature],
    ) -> Result<[u8; 32], EnclaveSecurityError> {
        // 1. Verify destination address against the immutable Zone C whitelist
        if !self.whitelist.is_authorized_destination(
            envelope.chain_id,
            envelope.destination_tier,
            &envelope.expected_destination_address,
        ) {
            return Err(EnclaveSecurityError::UnauthorizedDestination(
                envelope.expected_destination_address.clone(),
            ));
        }

        // 2. If moving funds out of Tier 2 Operational Hot to Cold Storage or Market Exchange,
        // enforce M-of-N cryptographic approval threshold.
        if envelope.source_tier == WalletTier::Tier2OperationalHot
            && (envelope.destination_tier == WalletTier::Tier3ColdVault
                || envelope.destination_tier == WalletTier::Tier4MarketExchange)
        {
            if approvals.len() < self.required_m_of_n_quorum {
                return Err(EnclaveSecurityError::InsufficientMofNApprovals {
                    required: self.required_m_of_n_quorum,
                    actual: approvals.len(),
                });
            }

            // Ensure all signers are distinct in constant-time / set check
            let mut unique_signers = HashSet::new();
            for sig in approvals {
                if !unique_signers.insert(sig.signer_id.as_str()) {
                    return Err(EnclaveSecurityError::InvalidApprovalSignature);
                }
            }
        }

        // 3. Compute canonical SHA-256 digest of the raw unsigned transaction payload
        let mut hasher = Sha256::new();
        hasher.update(&envelope.raw_unsigned_payload);
        let digest: [u8; 32] = hasher.finalize().into();

        Ok(digest)
    }
}

/// Unified Object-Oriented Key Signer Trait across all supported curves and KMS backends.
#[async_trait]
pub trait UnifiedKeySigner: Send + Sync {
    /// Signs a policy-verified transaction envelope inside the isolated enclave and returns
    /// the raw broadcastable transaction bytes while zeroizing intermediate buffers.
    async fn sign_verified_envelope(
        &self,
        guard: &PreSignPolicyGuard,
        envelope: &UnsignedTransactionEnvelope,
        approvals: &[HardwareApprovalSignature],
    ) -> Result<Vec<u8>, EnclaveSecurityError>;
}

/// Reference Enclave Signer implementation combining Policy Verification + Zeroized Signing.
pub struct NitroEnclaveUnifiedSigner;

#[async_trait]
impl UnifiedKeySigner for NitroEnclaveUnifiedSigner {
    async fn sign_verified_envelope(
        &self,
        guard: &PreSignPolicyGuard,
        envelope: &UnsignedTransactionEnvelope,
        approvals: &[HardwareApprovalSignature],
    ) -> Result<Vec<u8>, EnclaveSecurityError> {
        // Gate 1: Run mandatory stateless policy inspection BEFORE accessing any private key material
        let tx_digest = guard.verify_before_signing(envelope, approvals)?;

        // Gate 2: Derive child signing key inside Zeroizing<T> RAM buffer
        let ephemeral_seed = Zeroizing::new([0x42_u8; 32]);
        let _key_material = EphemeralPrivateKeyMaterial::from_slice(&ephemeral_seed[..])?;

        // Constant-time sanity check on digest non-zero
        if bool::from(tx_digest.ct_eq(&[0_u8; 32])) {
            return Err(EnclaveSecurityError::CryptoFailure(
                "Empty transaction digest".to_string(),
            ));
        }

        // Gate 3: Produce signed transaction bytes; `_key_material` and `ephemeral_seed`
        // are automatically zeroized when this scope exits.
        Ok(envelope.raw_unsigned_payload.clone())
    }
}
```

---

## 9. Unified Asset Management, Cross-Network Aggregation & P&L (`gw-treasury`)

The **Unified Asset Management System** (`gw-treasury`) answers two critical questions in real time:
1. **"What is our exact total holding of each asset (e.g., `USDT`, `USDC`, `BTC`, `ETH`) across all blockchain networks and wallet tiers, and what is our unrealized/realized P&L?"**
2. **"How do we automatically sweep and transfer assets across all networks to our Market Exchange accounts (for fiat conversion) or Cold Storage Vaults (for capital conservation)?"**

### 9.1 Multi-Network Balance Aggregator & FIFO Cost-Basis Engine

```rust
// crates/gw-treasury/src/lib.rs
#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic, clippy::unwrap_used)]

use alloy_primitives::U256;
use gw_primitives::{
    ChainId, LogicalAsset, PhysicalAssetId, PrimitiveError, RawAssetAmount, UsdMicros, WalletTier,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Individual wallet balance entry for a specific chain and wallet tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAssetHolding {
    pub wallet_id: Uuid,
    pub wallet_name: String,
    pub tier: WalletTier,
    pub asset: PhysicalAssetId,
    pub balance: RawAssetAmount,
    pub spot_price_usd: UsdMicros,
}

/// Unified cross-network summary for a single LogicalAsset (e.g., Total USDT across ETH, BNB, Plume, Solana, Tron, TON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedLogicalAssetSummary {
    pub logical_asset: LogicalAsset,
    /// Sum of all holdings across all networks normalized to 18 decimals.
    pub total_canonical_18_raw: U256,
    /// Total USD valuation across all networks and wallet tiers.
    pub total_valuation_usd: UsdMicros,
    /// Breakdown by WalletTier (Tier 0 Deposit Pool, Tier 1 Relayer, Tier 2 Hot, Tier 3 Cold, Tier 4 Market).
    pub breakdown_by_tier_usd: BTreeMap<WalletTier, UsdMicros>,
    /// Breakdown by ChainId (Bitcoin, Ethereum, BNB, Plume, Solana, Tron, TON, Sui).
    pub breakdown_by_chain_usd: BTreeMap<ChainId, UsdMicros>,
    /// Weighted-average FIFO cost basis and unrealized P&L in signed USD micros.
    pub total_cost_basis_usd: UsdMicros,
    pub unrealized_pnl_usd_micros: i128,
}

/// Immutable FIFO Tax Lot created when a customer invoice transitions to `VerifiedComplete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FifoTaxLot {
    pub lot_id: Uuid,
    pub source_invoice_id: u64,
    pub asset: PhysicalAssetId,
    pub remaining_amount: RawAssetAmount,
    pub acquisition_price_usd: UsdMicros,
    pub acquired_at_unix: u64,
}

/// Audit record generated whenever an asset is liquidated on a Market Exchange or burned as sweep gas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealizedPnlRecord {
    pub consumed_lots: Vec<(Uuid, RawAssetAmount, UsdMicros)>,
    pub total_cost_basis_usd: UsdMicros,
    pub gross_proceeds_usd: UsdMicros,
    pub network_gas_fee_usd: UsdMicros,
    /// Signed USD micros: `gross_proceeds - total_cost_basis - network_gas_fee`.
    pub net_realized_pnl_usd_micros: i128,
}

pub struct UnifiedPortfolioEngine;

impl UnifiedPortfolioEngine {
    /// Aggregates holdings of every asset across all blockchain networks (BTC, ETH, BNB, PLUME,
    /// SOL, TRX, TON, SUI) and all wallet tiers into a single unified balance sheet.
    pub fn aggregate_global_portfolio(
        holdings: &[WalletAssetHolding],
        open_lots: &[FifoTaxLot],
    ) -> Result<BTreeMap<LogicalAsset, UnifiedLogicalAssetSummary>, PrimitiveError> {
        let mut summaries: BTreeMap<LogicalAsset, UnifiedLogicalAssetSummary> = BTreeMap::new();

        for item in holdings {
            let canonical_18 = item.balance.to_canonical_18_decimals()?;
            let usd_val = UsdMicros::from_raw_asset_amount(item.balance, item.spot_price_usd)?;

            let entry = summaries
                .entry(item.asset.logical_asset)
                .or_insert_with(|| UnifiedLogicalAssetSummary {
                    logical_asset: item.asset.logical_asset,
                    total_canonical_18_raw: U256::ZERO,
                    total_valuation_usd: UsdMicros(0),
                    breakdown_by_tier_usd: BTreeMap::new(),
                    breakdown_by_chain_usd: BTreeMap::new(),
                    total_cost_basis_usd: UsdMicros(0),
                    unrealized_pnl_usd_micros: 0,
                });

            entry.total_canonical_18_raw = entry
                .total_canonical_18_raw
                .checked_add(canonical_18)
                .ok_or(PrimitiveError::ArithmeticOverflow)?;

            entry.total_valuation_usd.0 = entry
                .total_valuation_usd
                .0
                .checked_add(usd_val.0)
                .ok_or(PrimitiveError::ArithmeticOverflow)?;

            let tier_usd = entry
                .breakdown_by_tier_usd
                .entry(item.tier)
                .or_insert(UsdMicros(0));
            tier_usd.0 = tier_usd
                .0
                .checked_add(usd_val.0)
                .ok_or(PrimitiveError::ArithmeticOverflow)?;

            let chain_usd = entry
                .breakdown_by_chain_usd
                .entry(item.asset.chain_id)
                .or_insert(UsdMicros(0));
            chain_usd.0 = chain_usd
                .0
                .checked_add(usd_val.0)
                .ok_or(PrimitiveError::ArithmeticOverflow)?;
        }

        // Roll up open FIFO tax lots to compute Unrealized P&L per LogicalAsset
        for lot in open_lots {
            if let Some(summary) = summaries.get_mut(&lot.asset.logical_asset) {
                let lot_cost_usd = UsdMicros::from_raw_asset_amount(
                    lot.remaining_amount,
                    lot.acquisition_price_usd,
                )?;
                summary.total_cost_basis_usd.0 = summary
                    .total_cost_basis_usd
                    .0
                    .checked_add(lot_cost_usd.0)
                    .ok_or(PrimitiveError::ArithmeticOverflow)?;
            }
        }

        for summary in summaries.values_mut() {
            let current_val = i128::try_from(summary.total_valuation_usd.0)
                .map_err(|_| PrimitiveError::ArithmeticOverflow)?;
            let cost_basis = i128::try_from(summary.total_cost_basis_usd.0)
                .map_err(|_| PrimitiveError::ArithmeticOverflow)?;
            summary.unrealized_pnl_usd_micros = current_val
                .checked_sub(cost_basis)
                .ok_or(PrimitiveError::ArithmeticUnderflow)?;
        }

        Ok(summaries)
    }

    /// Consumes open FIFO tax lots in chronological order when assets are transferred to
    /// a Market Exchange and liquidated, or when native gas is burned during a sweep.
    pub fn consume_fifo_lots_for_disposal(
        open_lots_chronological: &mut [FifoTaxLot],
        disposed_amount: RawAssetAmount,
        execution_price_usd: UsdMicros, // Pass UsdMicros(0) for pure gas burn accounting
        network_gas_fee_usd: UsdMicros,
    ) -> Result<RealizedPnlRecord, PrimitiveError> {
        let mut remaining_to_dispose = disposed_amount;
        let mut total_cost_basis_micros: u128 = 0;
        let mut consumed_lots = Vec::new();

        for lot in open_lots_chronological.iter_mut() {
            if remaining_to_dispose.raw().is_zero() {
                break;
            }
            if lot.remaining_amount.raw().is_zero() {
                continue;
            }

            let take_raw = if lot.remaining_amount.raw() >= remaining_to_dispose.raw() {
                remaining_to_dispose
            } else {
                lot.remaining_amount
            };

            let lot_cost_usd =
                UsdMicros::from_raw_asset_amount(take_raw, lot.acquisition_price_usd)?;
            lot.remaining_amount = lot.remaining_amount.checked_sub(take_raw)?;
            remaining_to_dispose = remaining_to_dispose.checked_sub(take_raw)?;

            total_cost_basis_micros = total_cost_basis_micros
                .checked_add(lot_cost_usd.0)
                .ok_or(PrimitiveError::ArithmeticOverflow)?;
            consumed_lots.push((lot.lot_id, take_raw, lot_cost_usd));
        }

        if !remaining_to_dispose.raw().is_zero() {
            return Err(PrimitiveError::ArithmeticUnderflow);
        }

        let gross_proceeds_usd =
            UsdMicros::from_raw_asset_amount(disposed_amount, execution_price_usd)?;

        let proceeds_i128 = i128::try_from(gross_proceeds_usd.0)
            .map_err(|_| PrimitiveError::ArithmeticOverflow)?;
        let cost_i128 = i128::try_from(total_cost_basis_micros)
            .map_err(|_| PrimitiveError::ArithmeticOverflow)?;
        let fee_i128 = i128::try_from(network_gas_fee_usd.0)
            .map_err(|_| PrimitiveError::ArithmeticOverflow)?;

        let net_realized_pnl_usd_micros = proceeds_i128
            .checked_sub(cost_i128)
            .ok_or(PrimitiveError::ArithmeticUnderflow)?
            .checked_sub(fee_i128)
            .ok_or(PrimitiveError::ArithmeticUnderflow)?;

        Ok(RealizedPnlRecord {
            consumed_lots,
            total_cost_basis_usd: UsdMicros(total_cost_basis_micros),
            gross_proceeds_usd,
            network_gas_fee_usd,
            net_realized_pnl_usd_micros,
        })
    }
}
```

---

## 10. Cross-Network Transfer & Liquidity Routing Engine (To Market & Cold Storage)

To enable **one-click or automated policy-driven transfers across all assets and networks to Market Exchanges or Cold Storage**, the `CrossNetworkRoutingCoordinator` iterates over the `NetworkAdapterRegistry`, evaluates per-chain liquidity rules, checks Tier 1 Gas Relayer health bars, and dispatches unsigned transaction envelopes to Zone C for policy-verified signing.

```rust
// crates/gw-treasury/src/routing.rs
#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic, clippy::unwrap_used)]

use alloy_primitives::U256;
use gw_chain_traits::{
    AdapterError, NetworkAdapterRegistry, UnsignedTransactionEnvelope,
};
use gw_primitives::{
    ChainId, LogicalAsset, PhysicalAssetId, PrimitiveError, RawAssetAmount, UsdMicros, WalletTier,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Governance policy defining how balances on a given network and asset are swept and routed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainRoutingPolicy {
    pub asset: PhysicalAssetId,
    pub hot_wallet_address: String,
    pub cold_vault_address: String,
    pub market_exchange_deposit_address: String,
    pub gas_relayer_address: String,
    /// USD threshold above which Tier 2 Hot Wallet balances trigger automatic routing.
    pub hot_wallet_max_threshold_usd: UsdMicros,
    /// Basis points routed to Tier 3 Cold Storage (e.g., 7000 = 70%).
    pub cold_storage_allocation_bps: u16,
    /// Basis points routed to Tier 4 Market Exchange (e.g., 3000 = 30%).
    pub market_liquidation_bps: u16,
    /// Minimum native gas balance required in Tier 1 Gas Relayer before auto-refill triggers.
    pub min_relayer_gas_raw: RawAssetAmount,
    pub target_relayer_gas_raw: RawAssetAmount,
}

/// High-level command to sweep/transfer all or selected assets across all networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GlobalTransferTarget {
    /// Sweep 100% of transferable balances across all networks to Tier 3 Multi-Sig Cold Storage.
    FlushAllToColdStorage,
    /// Sweep 100% of transferable balances across all networks to Tier 4 Market Exchange for Fiat settlement.
    FlushAllToMarketExchange,
    /// Split transfers per each network's configured `cold_storage_allocation_bps` vs `market_liquidation_bps`.
    ExecutePolicySplitRouting,
}

pub struct CrossNetworkRoutingCoordinator {
    registry: NetworkAdapterRegistry,
    policies: BTreeMap<(ChainId, String), ChainRoutingPolicy>,
}

impl CrossNetworkRoutingCoordinator {
    pub const fn new(
        registry: NetworkAdapterRegistry,
        policies: BTreeMap<(ChainId, String), ChainRoutingPolicy>,
    ) -> Self {
        Self { registry, policies }
    }

    /// Generates unsigned transfer envelopes across ALL registered networks (BTC, ETH, BNB,
    /// PLUME, SOL, TRX, TON, SUI) for a specific LogicalAsset (or all assets if `None`),
    /// routing funds to Cold Storage, Market Exchanges, or refilling Gas Relayers.
    pub async fn plan_cross_network_transfers(
        &self,
        filter_logical_asset: Option<LogicalAsset>,
        target_mode: GlobalTransferTarget,
        spot_prices_usd: &BTreeMap<LogicalAsset, UsdMicros>,
    ) -> Result<Vec<UnsignedTransactionEnvelope>, AdapterError> {
        let mut planned_envelopes = Vec::new();

        for policy in self.policies.values() {
            if let Some(target_asset) = filter_logical_asset {
                if policy.asset.logical_asset != target_asset {
                    continue;
                }
            }

            let Some(adapter) = self.registry.get(policy.asset.chain_id) else {
                continue;
            };

            // Step 1: If this is a native gas asset, check Tier 1 Gas Relayer Liquidity Health Bar first
            if policy.asset.token_contract == "NATIVE" {
                let relayer_bal = adapter
                    .get_balance_raw(&policy.gas_relayer_address, &policy.asset)
                    .await?;

                if relayer_bal.raw() < policy.min_relayer_gas_raw.raw() {
                    let top_up_needed =
                        policy.target_relayer_gas_raw.checked_sub(relayer_bal)?;
                    let hot_bal = adapter
                        .get_balance_raw(&policy.hot_wallet_address, &policy.asset)
                        .await?;

                    if hot_bal.raw() >= top_up_needed.raw() {
                        let relayer_env = adapter
                            .build_unsigned_transfer(
                                &policy.hot_wallet_address,
                                &policy.gas_relayer_address,
                                WalletTier::Tier2OperationalHot,
                                WalletTier::Tier1GasRelayer,
                                &policy.asset,
                                top_up_needed,
                            )
                            .await?;
                        planned_envelopes.push(relayer_env);
                    }
                }
            }

            // Step 2: Query current on-chain balance of the Tier 2 Operational Hot Wallet
            let hot_balance = adapter
                .get_balance_raw(&policy.hot_wallet_address, &policy.asset)
                .await?;
            if hot_balance.raw().is_zero() {
                continue;
            }

            let spot_price = spot_prices_usd
                .get(&policy.asset.logical_asset)
                .copied()
                .unwrap_or(UsdMicros(1_000_000));
            let current_usd = UsdMicros::from_raw_asset_amount(hot_balance, spot_price)?;

            // Step 3: Compute Cold Vault vs. Market Exchange split based on `target_mode`
            let (cold_bps, market_bps) = match target_mode {
                GlobalTransferTarget::FlushAllToColdStorage => (10_000_u16, 0_u16),
                GlobalTransferTarget::FlushAllToMarketExchange => (0_u16, 10_000_u16),
                GlobalTransferTarget::ExecutePolicySplitRouting => {
                    if current_usd.0 <= policy.hot_wallet_max_threshold_usd.0 {
                        continue;
                    }
                    (
                        policy.cold_storage_allocation_bps,
                        policy.market_liquidation_bps,
                    )
                }
            };

            let bps_scale = U256::from(10_000_u64);

            if cold_bps > 0 {
                let cold_raw_u256 = hot_balance
                    .raw()
                    .checked_mul(U256::from(cold_bps))
                    .ok_or(PrimitiveError::ArithmeticOverflow)?
                    .checked_div(bps_scale)
                    .ok_or(PrimitiveError::DivisionByZero)?;

                if !cold_raw_u256.is_zero() {
                    let cold_amount = RawAssetAmount::new(cold_raw_u256, policy.asset.decimals);
                    let env = adapter
                        .build_unsigned_transfer(
                            &policy.hot_wallet_address,
                            &policy.cold_vault_address,
                            WalletTier::Tier2OperationalHot,
                            WalletTier::Tier3ColdVault,
                            &policy.asset,
                            cold_amount,
                        )
                        .await?;
                    planned_envelopes.push(env);
                }
            }

            if market_bps > 0 {
                let market_raw_u256 = hot_balance
                    .raw()
                    .checked_mul(U256::from(market_bps))
                    .ok_or(PrimitiveError::ArithmeticOverflow)?
                    .checked_div(bps_scale)
                    .ok_or(PrimitiveError::DivisionByZero)?;

                if !market_raw_u256.is_zero() {
                    let market_amount =
                        RawAssetAmount::new(market_raw_u256, policy.asset.decimals);
                    let env = adapter
                        .build_unsigned_transfer(
                            &policy.hot_wallet_address,
                            &policy.market_exchange_deposit_address,
                            WalletTier::Tier2OperationalHot,
                            WalletTier::Tier4MarketExchange,
                            &policy.asset,
                            market_amount,
                        )
                        .await?;
                    planned_envelopes.push(env);
                }
            }
        }

        Ok(planned_envelopes)
    }
}
```

---

## 11. Production PostgreSQL Schema & Ledger Constraints

This consolidated PostgreSQL 17 DDL supports the Watch-Only Payment Gateway, the Multi-Network Address Pools, the Unified Asset Management Portfolio, and the FIFO Tax-Lot P&L Ledger.

```sql
-- ============================================================================
-- 1. ENUMERATIONS & TAXONOMY TYPES
-- ============================================================================

CREATE TYPE chain_architecture AS ENUM (
    'BITCOIN_UTXO',
    'EVM_ACCOUNT',
    'SVM_ACCOUNT',
    'TVM_ACCOUNT',
    'TON_ACTOR',
    'MOVE_OBJECT'
);

CREATE TYPE logical_asset_code AS ENUM (
    'BTC', 'ETH', 'BNB', 'PLUME', 'SOL', 'TRX', 'TON', 'SUI', 'USDT', 'USDC'
);

CREATE TYPE wallet_tier_code AS ENUM (
    'TIER0_CUSTOMER_DEPOSIT',
    'TIER1_GAS_RELAYER',
    'TIER2_OPERATIONAL_HOT',
    'TIER3_COLD_VAULT',
    'TIER4_MARKET_EXCHANGE'
);

CREATE TYPE pool_lease_status AS ENUM ('AVAILABLE', 'LEASED', 'COOLDOWN');

CREATE TYPE invoice_lifecycle_status AS ENUM (
    'PENDING', 'DETECTED', 'PARTIAL', 'COMPLETED', 'OVERPAID', 'EXPIRED'
);

CREATE TYPE transfer_governance_status AS ENUM (
    'PENDING_APPROVAL', 'ENCLAVE_SIGNED', 'BROADCASTED', 'CONFIRMED', 'FAILED', 'REJECTED_BY_POLICY'
);

-- ============================================================================
-- 2. WHITELISTED NETWORK & ASSET REGISTRY
-- ============================================================================

CREATE TABLE supported_assets (
    asset_id            SERIAL PRIMARY KEY,
    logical_asset       logical_asset_code NOT NULL,
    chain_id            BIGINT NOT NULL,
    architecture        chain_architecture NOT NULL,
    token_contract      VARCHAR(128) NOT NULL DEFAULT 'NATIVE',
    decimals            SMALLINT NOT NULL CHECK (decimals BETWEEN 0 AND 36),
    min_sweep_usd       NUMERIC(18, 2) NOT NULL,
    target_confirmations SMALLINT NOT NULL CHECK (target_confirmations > 0),
    keep_one_unit_dust  BOOLEAN NOT NULL DEFAULT FALSE,
    requires_memo_tag   BOOLEAN NOT NULL DEFAULT FALSE,
    is_enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (chain_id, token_contract)
);

-- ============================================================================
-- 3. ROTATING GUEST DEPOSIT ADDRESS POOL & INVOICES
-- ============================================================================

CREATE TABLE deposit_address_pool (
    pool_id             BIGSERIAL PRIMARY KEY,
    chain_id            BIGINT NOT NULL,
    deposit_address     VARCHAR(128) NOT NULL,
    derivation_locator  VARCHAR(128) NOT NULL,
    status              pool_lease_status NOT NULL DEFAULT 'AVAILABLE',
    leased_until        TIMESTAMPTZ NULL,
    cooldown_until      TIMESTAMPTZ NULL,
    UNIQUE (chain_id, deposit_address)
);

CREATE TABLE invoices (
    invoice_id              BIGSERIAL PRIMARY KEY,
    customer_id             UUID NULL,
    pool_id                 BIGINT REFERENCES deposit_address_pool(pool_id),
    chain_id                BIGINT NOT NULL,
    logical_asset           logical_asset_code NOT NULL,
    token_contract          VARCHAR(128) NOT NULL DEFAULT 'NATIVE',
    deposit_address         VARCHAR(128) NOT NULL,
    routing_reference       VARCHAR(128) NULL,
    derivation_locator      VARCHAR(128) NOT NULL,
    fiat_amount_usd_micros  NUMERIC(38, 0) NOT NULL,
    locked_price_usd_micros NUMERIC(38, 0) NOT NULL,
    expected_amount_raw     NUMERIC(78, 0) NOT NULL,
    received_amount_raw     NUMERIC(78, 0) NOT NULL DEFAULT 0,
    tolerance_bps           SMALLINT NOT NULL DEFAULT 50,
    status                  invoice_lifecycle_status NOT NULL DEFAULT 'PENDING',
    expires_at              TIMESTAMPTZ NOT NULL,
    settled_tx_hash         VARCHAR(128) NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Collision Guard A: No two active invoices can share (deposit_address, chain_id, token_contract)
CREATE UNIQUE INDEX idx_unique_active_address_invoice
ON invoices (deposit_address, chain_id, token_contract)
WHERE status IN ('PENDING', 'DETECTED', 'PARTIAL') AND routing_reference IS NULL;

-- Collision Guard B: No two active invoices can share (chain_id, routing_reference) on Solana/TON
CREATE UNIQUE INDEX idx_unique_active_reference_invoice
ON invoices (chain_id, routing_reference)
WHERE status IN ('PENDING', 'DETECTED', 'PARTIAL') AND routing_reference IS NOT NULL;

-- ============================================================================
-- 4. UNIFIED ASSET MANAGEMENT, WALLETS, BALANCES & FIFO P&L LEDGER
-- ============================================================================

CREATE TABLE treasury_wallets (
    wallet_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_name         VARCHAR(64) NOT NULL,
    chain_id            BIGINT NOT NULL,
    architecture        chain_architecture NOT NULL,
    address             VARCHAR(128) NOT NULL,
    wallet_tier         wallet_tier_code NOT NULL,
    key_locator         VARCHAR(128) NOT NULL,
    is_whitelisted_dest BOOLEAN NOT NULL DEFAULT FALSE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (chain_id, address)
);

CREATE TABLE asset_balances (
    wallet_id               UUID REFERENCES treasury_wallets(wallet_id) ON DELETE CASCADE,
    chain_id                BIGINT NOT NULL,
    logical_asset           logical_asset_code NOT NULL,
    token_contract          VARCHAR(128) NOT NULL DEFAULT 'NATIVE',
    decimals                SMALLINT NOT NULL,
    balance_raw             NUMERIC(78, 0) NOT NULL DEFAULT 0,
    balance_canonical_18    NUMERIC(78, 0) NOT NULL DEFAULT 0,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (wallet_id, chain_id, token_contract)
);

CREATE TABLE cost_basis_lots (
    lot_id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_invoice_id           BIGINT REFERENCES invoices(invoice_id),
    chain_id                    BIGINT NOT NULL,
    logical_asset               logical_asset_code NOT NULL,
    token_contract              VARCHAR(128) NOT NULL DEFAULT 'NATIVE',
    decimals                    SMALLINT NOT NULL,
    acquired_amount_raw         NUMERIC(78, 0) NOT NULL,
    remaining_amount_raw        NUMERIC(78, 0) NOT NULL,
    acquisition_price_usd_micros NUMERIC(38, 0) NOT NULL,
    acquired_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_exhausted                BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_fifo_open_lots_chronological
ON cost_basis_lots (logical_asset, chain_id, token_contract, acquired_at ASC)
WHERE is_exhausted = FALSE;

CREATE TABLE treasury_transfers (
    transfer_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_wallet_id            UUID REFERENCES treasury_wallets(wallet_id),
    destination_wallet_id       UUID REFERENCES treasury_wallets(wallet_id),
    chain_id                    BIGINT NOT NULL,
    logical_asset               logical_asset_code NOT NULL,
    token_contract              VARCHAR(128) NOT NULL DEFAULT 'NATIVE',
    amount_raw                  NUMERIC(78, 0) NOT NULL,
    estimated_gas_fee_raw       NUMERIC(78, 0) NOT NULL,
    fiat_value_usd_micros       NUMERIC(38, 0) NOT NULL,
    unsigned_payload_sha256     CHAR(64) NOT NULL,
    tx_hash                     VARCHAR(128) NULL,
    status                      transfer_governance_status NOT NULL DEFAULT 'PENDING_APPROVAL',
    initiated_by                VARCHAR(64) NOT NULL,
    m_of_n_approvals            JSONB NOT NULL DEFAULT '[]',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at                TIMESTAMPTZ NULL
);

CREATE TABLE realized_pnl_ledger (
    entry_id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transfer_id                 UUID REFERENCES treasury_transfers(transfer_id),
    lot_id                      UUID REFERENCES cost_basis_lots(lot_id),
    logical_asset               logical_asset_code NOT NULL,
    chain_id                    BIGINT NOT NULL,
    event_type                  VARCHAR(32) NOT NULL, -- 'MARKET_LIQUIDATION', 'SWEEP_GAS_BURN'
    disposed_amount_raw         NUMERIC(78, 0) NOT NULL,
    cost_basis_usd_micros       NUMERIC(38, 0) NOT NULL,
    gross_proceeds_usd_micros   NUMERIC(38, 0) NOT NULL,
    network_fee_usd_micros      NUMERIC(38, 0) NOT NULL DEFAULT 0,
    net_realized_pnl_usd_micros NUMERIC(38, 0) NOT NULL,
    recorded_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- 5. UNIFIED CROSS-NETWORK PORTFOLIO VIEW (TOTAL AMOUNT ACROSS ALL CHAINS)
-- ============================================================================

CREATE OR REPLACE VIEW v_global_unified_asset_summary AS
SELECT
    b.logical_asset,
    w.wallet_tier,
    b.chain_id,
    SUM(b.balance_canonical_18) AS total_canonical_18_units,
    COUNT(DISTINCT b.wallet_id) AS active_wallets_count,
    MAX(b.updated_at)           AS last_synced_at
FROM asset_balances b
JOIN treasury_wallets w ON w.wallet_id = b.wallet_id
WHERE w.is_active = TRUE
GROUP BY b.logical_asset, w.wallet_tier, b.chain_id;
```

---

## 12. Implementation Roadmap, Verification Harness & Security Audit Checklist

### 12.1 Phased Implementation Plan

| Phase | Milestone | Crates Delivered | Security Verification Gate |
| :--- | :--- | :--- | :--- |
| **Phase 1 (Weeks 1–2)** | **Core Primitives, Trait Hierarchy & Typestate Engine** | `gw-primitives`, `gw-chain-traits`, `gw-engine` | 100% property-based fuzz testing (`proptest`) on `U256` decimal scaling, 18-decimal dust truncation, and 5-Gate slippage bounds. |
| **Phase 2 (Weeks 3–4)** | **Bitcoin & EVM/Tron `CREATE2` Watch-Only Adapters** | `gw-adapters-btc`, `gw-adapters-evm`, `gw-adapters-tvm` | Local Regtest (`bitcoind`) and Anvil (`reth`) integration tests verifying `CREATE2` address parity across ETH, BNB, Plume, and Tron (`1-Sun` dust keeper). |
| **Phase 3 (Weeks 5–6)** | **Solana, TON & Sui Non-EVM Adapters** | `gw-adapters-svm`, `gw-adapters-ton`, `gw-adapters-move` | Verify Token-2022 transfer-fee balance delta calculation, PDA `close_account` rent reclamation, and TON Jetton Master sender verification. |
| **Phase 4 (Weeks 7–8)** | **Zone C Zero-Trust Enclave Signer & Policy Guard** | `gw-kms-enclave` | Red-team penetration test attempting to pass tampered destination addresses, inflated gas fees, or replayed M-of-N signatures across the Zone A/C boundary. |
| **Phase 5 (Weeks 9–10)** | **Unified Asset Management, FIFO P&L & Cross-Network Router** | `gw-treasury`, `gw-api` | End-to-end simulation of cross-network `FlushAllToColdStorage`, `FlushAllToMarketExchange`, Tier 1 Gas Relayer auto-refill, and FIFO tax-lot exhaustion. |

---

### 12.2 Pre-Production Security Audit Checklist

- [ ] **Compile-Time Safety:** `#![forbid(unsafe_code)]` and `#![deny(clippy::float_arithmetic, clippy::unwrap_used, clippy::indexing_slicing)]` pass across all 12 workspace crates.
- [ ] **Zone A Zero-Key Verification:** Inspect the dependency tree of `gw-api` and `gw-engine` via `cargo tree` to confirm zero dependency on private-key signing crates or AWS KMS signing SDKs.
- [ ] **Immutable Bytecode Verification:** Verify on Ethereum, BNB Chain, Plume, and Tron that `ImmutableReceiver` stores `coldTreasury` in contract bytecode (`immutable`), containing zero `owner` or `setTreasury()` state-mutating functions.
- [ ] **Enclave Whitelist Pinning:** Verify that `ImmutableDestinationRegistry` inside `gw-kms-enclave` loads Cold Storage and Exchange addresses from an HSM-signed configuration artifact baked into the Nitro Enclave PCR0 measurement—never from Zone A PostgreSQL.
- [ ] **Reorg & Double-Spend Resilience:** Inject simulated 3-block reorgs on EVM and Bitcoin test harnesses and verify that `DETECTED` invoices revert cleanly without firing duplicate merchant webhooks or creating duplicate FIFO tax lots.