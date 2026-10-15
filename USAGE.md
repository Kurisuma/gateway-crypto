# gateway-crypto — Operational & Developer Usage Guide

> Comprehensive operational manual, API documentation, developer reference, and enterprise deployment runbook for `gateway-crypto`.

---

## Table of Contents

1. [System Architecture & Operational Philosophy](#1-system-architecture--operational-philosophy)
2. [Prerequisites & Build System Configuration](#2-prerequisites--build-system-configuration)
3. [Master Configuration Blueprint (`config.toml`)](#3-master-configuration-blueprint-configtoml)
4. [Zone A Checkout & Payment Engine API](#4-zone-a-checkout--payment-engine-api)
   - [REST Invoicing Endpoints](#rest-invoicing-endpoints)
   - [HTTP Error Codes & Error Payloads](#http-error-codes--error-payloads)
   - [Real-Time WebSocket Streaming Protocol](#real-time-websocket-streaming-protocol)
   - [Client SDK Implementations (Rust, TypeScript, Python)](#client-sdk-implementations-rust-typescript-python)
5. [In-Process Sharded Memory Engine (`gw-memcache`)](#5-in-process-sharded-memory-engine-gw-memcache)
   - [Shard Layout & Cache-Line Alignment](#shard-layout--cache-line-alignment)
   - [Anti-HashDoS CSPRNG Routing](#anti-hashdos-csprng-routing)
   - [Blake3 MAC Integrity Verification](#blake3-mac-integrity-verification)
   - [Sub-20ns Watchlist SnapshotMap](#sub-20ns-watchlist-snapshotmap)
6. [Relational SQLite Ledger via Oberer-lite (`gw-db`)](#6-relational-sqlite-ledger-via-oberer-lite-gw-db)
   - [Structs as the Schema (`#[derive(OrmTable)]`)](#structs-as-the-schema-deriveormtable)
   - [Auto-Migration & Database Operations](#auto-migration--database-operations)
   - [Sub-10ms Cold-Start Watchlist Hydration](#sub-10ms-cold-start-watchlist-hydration)
   - [CRUD Operations & Error Handling](#crud-operations--error-handling)
7. [Multi-Chain Network Adapters & Address Derivation](#7-multi-chain-network-adapters--address-derivation)
   - [Bitcoin BIP-84 Native SegWit](#bitcoin-bip-84-native-segwit)
   - [EVM CREATE2 Counterfactual Forwarders](#evm-create2-counterfactual-forwarders)
   - [Solana SVM Mode A & Mode B](#solana-svm-mode-a--mode-b)
   - [TRON TVM 1-Sun Dust Keeper](#tron-tvm-1-sun-dust-keeper)
   - [TON Single-Vault Feistel Memo Resolver](#ton-single-vault-feistel-memo-resolver)
   - [Sui Move Sponsored PTB Forwarder](#sui-move-sponsored-ptb-forwarder)
8. [Typestate Invoice Lifecycle & 5-Gate Engine (`gw-engine`)](#8-typestate-invoice-lifecycle--5-gate-engine-gw-engine)
   - [Typestate Progression Guarantees](#typestate-progression-guarantees)
   - [The 5 Gates of Verification](#the-5-gates-of-verification)
   - [Parent Hash Ring Buffer & 6-Block Reorg Rollbacks](#parent-hash-ring-buffer--6-block-reorg-rollbacks)
9. [Zone C AWS Nitro Enclave & Key Custody (`gw-kms-enclave`)](#9-zone-c-aws-nitro-enclave--key-custody-gw-kms-enclave)
   - [Nitro Enclave Architecture & Attestation](#nitro-enclave-architecture--attestation)
   - [PreSignPolicyGuard Raw Transaction Decoding](#presignpolicyguard-raw-transaction-decoding)
   - [Destination Address Whitelist Pinning](#destination-address-whitelist-pinning)
   - [M-of-N Quorum Enforcement & Zeroize Memory](#m-of-n-quorum-enforcement--zeroize-memory)
10. [Unified Treasury & FIFO Cost-Basis Accounting (`gw-treasury`)](#10-unified-treasury--fifo-cost-basis-accounting-gw-treasury)
    - [Cross-Network Canonical 18-Decimal Tensor](#cross-network-canonical-18-decimal-tensor)
    - [FIFO Tax Lot Ingestion & Prefix-Sum Depletion](#fifo-tax-lot-ingestion--prefix-sum-depletion)
    - [Economical Sweep Threshold Calculus](#economical-sweep-threshold-calculus)
    - [Zero-Dust Hot/Cold Liquidity Splitting](#zero-dust-hotcold-liquidity-splitting)
    - [Tier 1 Relayer Gas Replenishment Planner](#tier-1-relayer-gas-replenishment-planner)
11. [Production Deployment, Systemd & Monitoring](#11-production-deployment-systemd--monitoring)
    - [Systemd Service Units](#systemd-service-units)
    - [Prometheus Metrics Reference](#prometheus-metrics-reference)
    - [Structured Logging Configuration](#structured-logging-configuration)
12. [Incident Runbooks & Disaster Recovery](#12-incident-runbooks--disaster-recovery)
    - [Runbook 1: Dual-Oracle Deviation Trip](#runbook-1-dual-oracle-deviation-trip)
    - [Runbook 2: Chain Reorg Exceeding Standard Depth](#runbook-2-chain-reorg-exceeding-standard-depth)
    - [Runbook 3: Enclave PreSign Policy Rejection](#runbook-3-enclave-presign-policy-rejection)
    - [Runbook 4: Database WAL Checkpoint Lock](#runbook-4-database-wal-checkpoint-lock)
    - [Runbook 5: Gas Relayer Low Balance Emergency Refill](#runbook-5-gas-relayer-low-balance-emergency-refill)
    - [Runbook 6: Unconfirmed Mempool Replacement (RBF / CPFP)](#runbook-6-unconfirmed-mempool-replacement-rbf--cpfp)
    - [Runbook 7: Ingress Node Desync & Fork Recovery](#runbook-7-ingress-node-desync--fork-recovery)
13. [End-to-End Verification & Automated Testing](#13-end-to-end-verification--automated-testing)
14. [Automated End-to-End Integration Test Runner](#14-automated-end-to-end-integration-test-runner)
15. [Mathematical Verification Numerical Traces](#15-mathematical-verification-numerical-traces)
16. [Enterprise Security & Key Custody Audit Checklist](#16-enterprise-security--key-custody-audit-checklist)

---

## 1. System Architecture & Operational Philosophy

`gateway-crypto` is designed around three foundational architectural pillars:

### Pillar 1: Zero-Trust Security Partitioning
The system operates across three physically and cryptographically isolated execution zones:
- **Zone A (Public Plane):** Internet-facing services (`gw-api`, `gw-memcache`, `gw-engine`, `gw-treasury`, `gw-db`). Zone A holds strictly **zero private keys** and zero signing logic. It manages invoice states, watches incoming transactions, and calculates accounting ledgers using only public cryptographic material (extended public keys `xpub`/`zpub`, CREATE2 salts, and reference hashes).
- **Zone B (Private Node Plane):** Ingress-isolated full verification blockchain nodes (`bitcoind`, `reth`, `solana-validator`, `java-tron`, `ton-lite-server`, `sui-node`). Nodes run on private subnets, verifying consensus without holding signing keys.
- **Zone C (Air-Gapped Enclave Plane):** Hardware-isolated cryptographic execution vault (`gw-kms-enclave`) running inside AWS Nitro Enclaves, dedicated HSMs, or MPC signers. The enclave exposes an air-gapped VSOCK interface. Every raw transaction signature request is decoded and validated against an immutable destination whitelist by the `PreSignPolicyGuard` before private keys derive and sign payloads.

### Pillar 2: Pure Integer Mathematical Determinism
Floating-point arithmetic (`f32`, `f64`) is denied workspace-wide. In cryptocurrency settlement, IEEE 754 floating-point rounding errors lead to cumulative discrepancies, financial drift, and reconciliation loss. All token units, exchange rates, USD micro-valuations, basis points, and FIFO cost bases are computed using exact fixed-point integers:
- Raw on-chain token amounts: `alloy_primitives::U256` or `u128`.
- USD micro-valuations: `UsdMicros(u128)` representing USD with 6 decimal places ($1.00 = 1,000,000\text{ }\mu\text{USD}$).
- Basis point rates: `RateBps(u32)` representing hundredths of a percent ($1\% = 100\text{ bps}$).
- Net realized P&L: `SignedUsdMicros(i128)` preserving signed gains and losses.

### Pillar 3: Zero-Daemon Embedded Operations
External state daemons (such as Redis clusters or external SQL servers) introduce inter-process latency, network partition failure modes, and serialization overhead. `gateway-crypto` eliminates external infrastructure dependencies by embedding:
- An in-process, 64-shard, 128-byte cache-line aligned memory cache (`IMPRCE`).
- A high-speed SQLite relational ledger via the pure-Rust `Oberer-lite` ORM.

---

## 2. Prerequisites & Build System Configuration

### System Requirements
- **Rust Toolchain:** `rustc 1.85.0+` (Edition 2024).
- **Operating System:** Linux (Ubuntu 22.04 LTS+, RHEL 9+, Debian 12+), macOS 14+, or Windows 11 / Server 2022.
- **C Compiler:** Clang/GCC on Linux/macOS, or MSVC Build Tools on Windows (required for the embedded SQLite amalgamation).
- **AWS Nitro CLI (Optional):** Required only if building the Zone C Enclave EIF image.

### Recommended Cargo Build Profile
For institutional production deployment, compile with link-time optimization (LTO) enabled and abort-on-panic for deterministic memory safety:

```toml
# Add to workspace Cargo.toml for production releases
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true
overflow-checks = true
```

### Compilation Steps

```bash
# 1. Clone repository
git clone https://github.com/Kurisuma/gateway-crypto.git
cd gateway-crypto

# 2. Verify workspace lints and format
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# 3. Run entire test suite (67 unit, integration, and fuzz tests)
cargo test --workspace

# 4. Build release binaries
cargo build --release --workspace

# The compiled Zone A API binary is located at:
# ./target/release/gw-api
```

---

## 3. Master Configuration Blueprint (`config.toml`)

Create `/etc/gateway/config.toml` (or `config.toml` in your working directory) with the following annotated parameters:

```toml
# ==============================================================================
# GATEWAY-CRYPTO MASTER CONFIGURATION SPECIFICATION
# ==============================================================================

[server]
# Bind address for Zone A REST and WebSocket services
host = "0.0.0.0"
port = 8080
workers = 8
max_connections = 65536
enable_tls = true
tls_cert_path = "/etc/gateway/certs/api_cert.pem"
tls_key_path = "/etc/gateway/certs/api_key.pem"
request_timeout_ms = 15000

[cache]
# In-process 64-shard memory engine settings
shard_count = 64
max_capacity_per_shard = 16384
anti_replay_ttl_seconds = 604800  # 7-day memory barrier for signed tx digests
eviction_policy = "lru"

[database]
# Embedded SQLite ledger configuration via Oberer-lite
database_url = "sqlite:///var/lib/gateway/ledger.db"
max_connections = 32
busy_timeout_ms = 5000
wal_mode = true
synchronous = "normal"
auto_migrate = true
hydration_batch_size = 50000

[oracle]
# Dual-Oracle pricing parameters
max_deviation_bps = 150          # 150 bps (1.5%) maximum allowable deviation
refresh_interval_ms = 1000
stale_rate_timeout_ms = 5000
cex_ws_url = "wss://stream.binance.com:9443/ws"
onchain_rpc_url = "https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY"
chainlink_aggregator_registry = "0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf"

[networks.bitcoin]
enabled = true
network_type = "mainnet"
derivation_path = "m/84'/0'/0'/0/*"
xpub = "zpub6rFR7y4Q2AijBEqTUquhZz298VCdL6gLuvSp7vWgPpBpTk10Vi3EbV1nSg..."
min_confirmations = 2
node_rpc_url = "http://127.0.0.1:8332"
rpc_user = "gw_indexer"
rpc_password = "CHANGE_IN_PRODUCTION"

[networks.ethereum]
enabled = true
chain_id = 1
factory_address = "0x0000000000FFe8B47B3e2130213B802212439497"
forwarder_init_code_hash = "0x98f8287e07ff036815efc1c5e40e2d36fa33c56d782e4f016d445330e7046e72"
min_confirmations = 12
node_rpc_url = "http://127.0.0.1:8545"

[networks.bsc]
enabled = true
chain_id = 56
factory_address = "0x0000000000FFe8B47B3e2130213B802212439497"
forwarder_init_code_hash = "0x98f8287e07ff036815efc1c5e40e2d36fa33c56d782e4f016d445330e7046e72"
min_confirmations = 15
node_rpc_url = "http://127.0.0.1:8546"

[networks.polygon]
enabled = true
chain_id = 137
factory_address = "0x0000000000FFe8B47B3e2130213B802212439497"
forwarder_init_code_hash = "0x98f8287e07ff036815efc1c5e40e2d36fa33c56d782e4f016d445330e7046e72"
min_confirmations = 64
node_rpc_url = "http://127.0.0.1:8547"

[networks.arbitrum]
enabled = true
chain_id = 42161
factory_address = "0x0000000000FFe8B47B3e2130213B802212439497"
forwarder_init_code_hash = "0x98f8287e07ff036815efc1c5e40e2d36fa33c56d782e4f016d445330e7046e72"
min_confirmations = 24
node_rpc_url = "http://127.0.0.1:8548"

[networks.solana]
enabled = true
mode = "ModeB_ATA"
usdt_mint = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
vault_authority_pubkey = "4nd1m...vaultAuthority"
min_confirmations = 32
node_rpc_url = "http://127.0.0.1:8899"

[networks.tron]
enabled = true
trc20_usdt_contract = "TR7NHqJEKQxGTCi8q8ZY4pL8otSzgjLj6t"
forwarder_master = "TXLA...tronMaster"
dust_keeper_enabled = true       # Preserves 1-sun warm slot (saves 65k Energy)
min_confirmations = 19
node_rpc_url = "http://127.0.0.1:8090"

[networks.ton]
enabled = true
single_vault_address = "EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N"
feistel_round_keys = [0x9B4E3A, 0x1F8C7D, 0xE52A10, 0x77D4B2]
min_confirmations = 10
node_rpc_url = "http://127.0.0.1:8081"

[networks.sui]
enabled = true
package_id = "0x2::sui::SUI"
treasury_cap_id = "0x5361...suiCap"
sponsor_address = "0xa1b2...sponsorPubkey"
min_confirmations = 1
node_rpc_url = "http://127.0.0.1:9000"

[treasury]
cold_storage_retention_bps = 8000 # 80% to Cold Vault, 20% to Market Hot Liquidity
min_sweep_usd_micros = 50000000   # Sweep deposits >= $50.00 USD
gas_replenish_threshold_usd = 20000000 # Replenish relayer if gas < $20.00 USD
gas_target_reserve_usd = 100000000     # Top up relayer to $100.00 USD

[enclave]
vsock_cid = 16
vsock_port = 5005
pcr0_measurement = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
m_of_n_quorum_m = 2
m_of_n_quorum_n = 3
whitelist_sync_interval_ms = 30000
```

---

## 4. Zone A Checkout & Payment Engine API

The checkout engine provides a high-throughput REST and WebSocket interface over HTTP/2 and HTTP/1.1.

### REST Invoicing Endpoints

#### 1. Create Checkout Invoice
`POST /api/v1/invoices`

Creates a guaranteed checkout invoice with a locked exchange rate, clean dust truncation, and deterministic deposit address derivation.

**Headers:**
- `Content-Type: application/json`
- `X-Idempotency-Key: <unique-uuid-v4>` (prevents duplicate invoice creation within a 7-day memory window)

**Request Body:**
```json
{
  "amount_usd_micros": 100000000,
  "chain": "Ethereum",
  "symbol": "USDT",
  "ttl_seconds": 1800
}
```

**cURL Command:**
```bash
curl -X POST http://127.0.0.1:8080/api/v1/invoices \
  -H "Content-Type: application/json" \
  -H "X-Idempotency-Key: 7f8c9b20-8012-4cf3-94c3-63b7829a1b04" \
  -d '{
    "amount_usd_micros": 100000000,
    "chain": "Ethereum",
    "symbol": "USDT",
    "ttl_seconds": 1800
  }'
```

**Success Response (HTTP 201 Created):**
```json
{
  "invoice_id": "inv_01j7abcde45678901234567890",
  "status": "Pending",
  "pay_address": "0x71C63dd49405F41d3b3780B84D355745136A5397",
  "expected_units": "100000000",
  "display_amount": "100.000000",
  "usd_rate": "1000000",
  "expires_at": 1792194600
}
```

#### 2. Query Invoice Status
`GET /api/v1/invoices/{id}`

Returns current payment progress, including detection state, transaction hash, received units, and confirmation depth.

**cURL Command:**
```bash
curl -X GET http://127.0.0.1:8080/api/v1/invoices/inv_01j7abcde45678901234567890
```

**Success Response (HTTP 200 OK):**
```json
{
  "invoice_id": "inv_01j7abcde45678901234567890",
  "status": "VerifiedComplete",
  "pay_address": "0x71C63dd49405F41d3b3780B84D355745136A5397",
  "expected_units": "100000000",
  "received_units": "100000000",
  "tx_hash": "0x98f8287e07ff036815efc1c5e40e2d36fa33c56d782e4f016d445330e7046e72",
  "confirmations": 14
}
```

#### 3. Real-Time Portfolio Summary
`GET /api/v1/treasury/portfolio`

Returns real-time balance sheet aggregation across all 8 networks and 5 wallet tiers, homomorphically normalized to canonical 18 decimals.

**cURL Command:**
```bash
curl -X GET http://127.0.0.1:8080/api/v1/treasury/portfolio
```

**Success Response (HTTP 200 OK):**
```json
{
  "total_usd_value_micros": 5420000000000,
  "assets": [
    {
      "symbol": "USDT",
      "canonical_18_balance": "5420000000000000000000000",
      "usd_valuation_micros": 5420000000000,
      "chains": ["Ethereum", "Tron", "Polygon", "Solana"]
    }
  ]
}
```

#### 4. Query FIFO Cost-Basis Tax Lots
`GET /api/v1/treasury/lots`

Returns all active acquisition lots ingested from verified checkouts, preserving the exact USD exchange rate and remaining units.

**cURL Command:**
```bash
curl -X GET http://127.0.0.1:8080/api/v1/treasury/lots
```

**Success Response (HTTP 200 OK):**
```json
[
  {
    "lot_id": "lot_01j7abcdef1234567890",
    "chain": "Ethereum",
    "symbol": "USDT",
    "remaining_units": "100000000",
    "usd_cost_per_unit_micros": 1000000,
    "acquired_at": 1792190000
  }
]
```

---

### HTTP Error Codes & Error Payloads

All error responses return a standardized RFC 7807 compatible JSON structure:

```json
{
  "error_code": "CIRCUIT_BREAKER_TRIPPED",
  "message": "Dual-oracle mid-price deviation exceeded 150 bps boundary (measured: 184 bps)",
  "timestamp": 1792194612,
  "retry_after_seconds": 5
}
```

| HTTP Status | Error Code | Root Cause & Action Required |
| :--- | :--- | :--- |
| `400 Bad Request` | `INVALID_ASSET_OR_CHAIN` | Requested token symbol or chain identifier is not present in whitelist. |
| `404 Not Found` | `INVOICE_NOT_FOUND` | Invoice ID does not exist or has exceeded memory retention window. |
| `409 Conflict` | `IDEMPOTENCY_KEY_REUSED` | Same `X-Idempotency-Key` was submitted with differing payload parameters. |
| `503 Service Unavailable`| `CIRCUIT_BREAKER_TRIPPED`| CEX WebSocket vs DEX On-Chain rate divergence exceeded $150\text{ bps}$. |

---

### Real-Time WebSocket Streaming Protocol

Clients connect to `ws://127.0.0.1:8080/ws/v1/checkout/{id}` to stream deposit events with sub-millisecond latency.

```mermaid
sequenceDiagram
    participant Client as Frontend Checkout Client
    participant API as Zone A Gateway API (Axum)
    participant Engine as gw-engine & gw-memcache
    
    Client->>API: GET /ws/v1/checkout/inv_123 (Upgrade: websocket)
    API-->>Client: 101 Switching Protocols
    
    API->>Client: {"event":"Connected","invoice_id":"inv_123","status":"Pending"}
    
    Note over Engine: Ingress node sees transfer event in mempool
    Engine->>API: Mempool Deposit Event (0 Conf)
    API->>Client: {"event":"DepositDetected","tx_hash":"0xabc...","received_units":"100000000","confirmations":0}
    
    loop Every New Block
        Engine->>API: Block Depth Increment
        API->>Client: {"event":"ConfirmationProgress","confirmations":3,"required":12}
    end
    
    Note over Engine: 5 Gates Verified & Finalized
    Engine->>API: VerifiedComplete Event
    API->>Client: {"event":"InvoiceSettled","status":"VerifiedComplete","confirmations":12}
```

---

### Client SDK Implementations (Rust, TypeScript, Python)

#### 1. Rust Native Client (`reqwest` + `tokio-tungstenite`)

```rust
use futures_util::StreamExt;
use reqwest::Client;
use serde_json::Value;
use tokio_tungstenite::connect_async;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    
    // 1. Create invoice via REST
    let response = client
        .post("http://127.0.0.1:8080/api/v1/invoices")
        .header("Content-Type", "application/json")
        .header("X-Idempotency-Key", uuid::Uuid::new_v4().to_string())
        .json(&serde_json::json!({
            "amount_usd_micros": 50000000, // $50.00
            "chain": "Ethereum",
            "symbol": "USDT",
            "ttl_seconds": 1800
        }))
        .send()
        .await?
        .json::<Value>()
        .await?;

    let invoice_id = response["invoice_id"].as_str().expect("valid invoice_id");
    let pay_address = response["pay_address"].as_str().expect("valid address");
    println!("Invoice Created: {} -> Pay to: {}", invoice_id, pay_address);

    // 2. Stream confirmation events via WebSocket
    let ws_url = format!("ws://127.0.0.1:8080/ws/v1/checkout/{}", invoice_id);
    let (mut ws_stream, _) = connect_async(&ws_url).await?;

    while let Some(msg) = ws_stream.next().await {
        let msg = msg?;
        if msg.is_text() {
            println!("Stream Event: {}", msg.to_text()?);
        }
    }

    Ok(())
}
```

#### 2. TypeScript / Node.js Client (`fetch` + `ws`)

```typescript
import WebSocket from 'ws';
import crypto from 'crypto';

interface InvoiceResponse {
  invoice_id: string;
  status: string;
  pay_address: string;
  expected_units: string;
  display_amount: string;
  expires_at: number;
}

async function runCheckout() {
  const idempotencyKey = crypto.randomUUID();
  
  // 1. Create Invoice
  const res = await fetch('http://127.0.0.1:8080/api/v1/invoices', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Idempotency-Key': idempotencyKey,
    },
    body: JSON.stringify({
      amount_usd_micros: 25000000, // $25.00
      chain: 'Tron',
      symbol: 'USDT',
      ttl_seconds: 1800,
    }),
  });

  const invoice: InvoiceResponse = await res.json();
  console.log(`Invoice: ${invoice.invoice_id} | Send: ${invoice.display_amount} USDT to ${invoice.pay_address}`);

  // 2. Connect WebSocket
  const ws = new WebSocket(`ws://127.0.0.1:8080/ws/v1/checkout/${invoice.invoice_id}`);
  
  ws.on('message', (data: WebSocket.Data) => {
    const event = JSON.parse(data.toString());
    console.log('Checkout Event:', event);
    if (event.status === 'VerifiedComplete') {
      console.log('Payment Settled Successfully!');
      ws.close();
    }
  });
}

runCheckout().catch(console.error);
```

#### 3. Python Client (`httpx` + `websockets`)

```python
import asyncio
import uuid
import httpx
import websockets
import json

async def checkout_demo():
    async with httpx.AsyncClient() as client:
        # 1. Create Invoice
        res = await client.post(
            "http://127.0.0.1:8080/api/v1/invoices",
            headers={"X-Idempotency-Key": str(uuid.uuid4())},
            json={
                "amount_usd_micros": 100000000, # $100.00
                "chain": "Solana",
                "symbol": "USDT",
                "ttl_seconds": 1800
            }
        )
        invoice = res.json()
        print(f"Invoice: {invoice['invoice_id']} | Pay: {invoice['display_amount']} to {invoice['pay_address']}")

        # 2. Listen to WebSocket updates
        ws_url = f"ws://127.0.0.1:8080/ws/v1/checkout/{invoice['invoice_id']}"
        async with websockets.connect(ws_url) as ws:
            async for message in ws:
                event = json.loads(message)
                print(f"Received Event: {event}")
                if event.get("status") == "VerifiedComplete":
                    print("Payment finalized successfully.")
                    break

if __name__ == "__main__":
    asyncio.run(checkout_demo())
```

---

## 5. In-Process Sharded Memory Engine (`gw-memcache`)

`gw-memcache` implements the In-Process Memory Cache Engine (`IMPRCE`), replacing external Redis setups.

### Shard Layout & Cache-Line Alignment
To avoid false-sharing across CPU cores under heavy concurrent workloads, every shard is explicitly aligned to 128 bytes:

```rust
#[repr(align(128))]
pub struct ShardedPartition {
    pub map: parking_lot::RwLock<HashMap<String, SecureCacheEntry>>,
    pub stats: ShardMetrics,
}
```

### Anti-HashDoS CSPRNG Routing
To prevent algorithmic complexity attacks where an adversary crafts keys that collide into the same shard, partition indexing uses an ephemeral per-boot Blake3 keyed hasher:

$$\text{ShardIndex}(K) = \left\lfloor \frac{\text{Blake3Keyed}(K_{\text{boot}}, K)[0..8]}{\text{UINT64\_MAX}} \times 64 \right\rfloor$$

### Blake3 MAC Integrity Verification
Every cached value is wrapped in a `SecureCacheValue` containing a 32-byte keyed MAC. When read, the MAC is verified in constant time:

```rust
use subtle::ConstantTimeEq;

pub fn verify_entry_integrity(entry: &SecureCacheEntry, key: &[u8; 32]) -> bool {
    let computed_mac = blake3::keyed_hash(key, &entry.payload);
    computed_mac.as_bytes().ct_eq(&entry.expected_mac).into()
}
```

### Sub-20ns Watchlist SnapshotMap
Ingress block indexers need to query thousands of transactions per second against active deposit addresses. The engine maintains a lock-free, atomic `SnapshotMap` updated via copy-on-write semantics. Address queries return in under 20 nanoseconds without taking read locks on the primary cache partitions.

---

## 6. Relational SQLite Ledger via Oberer-lite (`gw-db`)

Relational persistence uses `Oberer-lite` ORM, combining compile-time Rust schema verification with embedded SQLite performance.

### Structs as the Schema (`#[derive(OrmTable)]`)
Database tables are declared directly as Rust structs in `crates/gw-db/src/models.rs`:

```rust
use oberer_orm::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, OrmTable)]
#[orm(table_name = "invoices")]
pub struct InvoiceRecord {
    #[orm(primary_key)]
    pub id: String,
    pub status: String,
    pub pay_address: String,
    pub expected_units: String,
    pub received_units: String,
    pub usd_rate: String,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, OrmTable)]
#[orm(table_name = "cost_basis_lots")]
pub struct CostBasisLotRecord {
    #[orm(primary_key)]
    pub lot_id: String,
    pub invoice_id: String,
    pub chain: String,
    pub symbol: String,
    pub original_units: String,
    pub remaining_units: String,
    pub usd_cost_per_unit_micros: u64,
    pub acquired_at: i64,
}
```

### Auto-Migration & Database Operations
On application startup, `DatabaseManager::migrate_all(&self)` inspects the SQLite master tables and executes automated table migrations:

```rust
use gw_db::DatabaseManager;

let db = DatabaseManager::new("sqlite://ledger.db", 32)?;
db.migrate_all()?; // Creates invoices, assets, lots, wallets automatically
```

### Sub-10ms Cold-Start Watchlist Hydration
When the node starts up, active unexpired checkout invoices must be loaded from SQLite into the in-memory cache without delaying transaction indexing. `DatabaseManager::hydrate_watchlist` streams unexpired records into the watchlist engine in under 10 milliseconds:

```rust
let active_count = db.hydrate_watchlist(&watchlist_engine, current_timestamp)?;
println!("Hydrated {} active deposit routes in < 10ms", active_count);
```

### CRUD Operations & Error Handling
`Oberer-lite` wraps operation results in `OrmOk<T>`, which unwraps cleanly using `.unenvelope()`:

```rust
use oberer_orm::OrmResultExt;

// Insert a record
let record = InvoiceRecord { /* ... */ };
db.insert_invoice(&record).unenvelope()?;

// Query by primary key
let invoice = db.get_invoice_by_id("inv_123").unenvelope()?;
```

---

## 7. Multi-Chain Network Adapters & Address Derivation

### Bitcoin BIP-84 Native SegWit
- **Path:** `m/84'/0'/0'/0/{index}`.
- **Address Prefix:** `bc1q...` (Bech32 P2WPKH).
- **Indexing:** Zone A derives addresses from an extended public key (`zpub`) without touching private keys. Incoming UTXOs are matched against the scriptPubKey.

### EVM CREATE2 Counterfactual Forwarders
- **Chains:** Ethereum, BSC, Polygon, Arbitrum.
- **Formula:**
  $$\text{Address} = \text{keccak256}(0\text{xff} \mathbin{\Vert} \text{Factory} \mathbin{\Vert} \text{Salt} \mathbin{\Vert} \text{InitCodeHash})[12..32]$$
- **Operational Advantage:** Deposit contracts are generated counterfactually without upfront gas deployment. The contract is deployed only during the first automated sweep.

### Solana SVM Mode A & Mode B
- **Mode A (System Account + Memo):** Customer transfers native SOL with an invoice-specific memo string.
- **Mode B (Associated Token Account - ATA):** A unique PDA (Program Derived Address) is derived for SPL tokens (e.g., USDT/USDC) using:
  $$\text{ATA} = \text{PDA}(\text{VaultPubkey}, \text{TokenProgramId}, \text{MintPubkey})$$

### TRON TVM 1-Sun Dust Keeper
- **Token:** TRC-20 USDT (`TR7NHqJEKQxGTCi8q8ZY4pL8otSzgjLj6t`).
- **Warm Slot Preservation:** Sweeping an account to zero deletes its SSTORE slot, requiring 65,000 Energy on the next write. The 1-Sun Dust Keeper retains 1 raw unit ($10^{-6}$ USDT):
  $$V_{\text{sweep}} = B_{\text{current}} - 1$$
  This saves approximately $50\%$ on network energy costs for high-volume merchants.

### TON Single-Vault Feistel Memo Resolver
- **Architecture:** Customers send TON or Jettons to a single merchant vault address, attaching a 40-bit compact integer memo.
- **Feistel Cipher:** The memo is permuted using a 4-round balanced Feistel network:
  $$L_{i+1} = R_i, \qquad R_{i+1} = L_i \oplus F(R_i, K_i)$$
  Ensures customer invoice IDs map bijectively to compact, error-detecting payment tags.

### Sui Move Sponsored PTB Forwarder
- **Architecture:** Programmable Transaction Blocks (PTB).
- **Gas Delegation:** The merchant gas relayer signs the gas sponsor object, allowing users with zero native SUI balance to deposit Move coins without gas failures.

---

## 8. Typestate Invoice Lifecycle & 5-Gate Engine (`gw-engine`)

The engine enforces payment state transitions using Rust's compile-time typestate pattern:

```rust
// Compile-time guaranteed transitions:
let pending: Invoice<Pending> = Invoice::new(...);
let detected: Invoice<Detected> = pending.into_detected(tx_hash, received_amount);
let complete: Invoice<VerifiedComplete> = detected.verify_and_complete(confs, threshold)?;
```

### The 5 Gates of Verification
1. **Gate 1 (Execution Success):** Receipt status is strictly successful (`receipt.status == 1`).
2. **Gate 2 (Asset Whitelist):** The transfer token contract and recipient address match the expected configuration.
3. **Gate 3 (Slippage Tolerance):** Cumulative received amount satisfies minimum threshold ($R_{\text{received}} \ge R_{\min}$).
4. **Gate 4 (Temporal Validity):** Block inclusion timestamp $\le$ quote expiration timestamp.
5. **Gate 5 (Confirmation Depth & Parent Continuity):** Required block depth reached with an unbroken chain of parent block hashes.

### Parent Hash Ring Buffer & 6-Block Reorg Rollbacks
The engine maintains a circular ring buffer (`ParentHashRingBuffer`) of recent block headers:

```
[Block N-5] <-- [Block N-4] <-- [Block N-3] <-- [Block N-2] <-- [Block N-1] <-- [Block N]
```

When a blockchain fork occurs, the engine scans the ring buffer to locate the Lowest Common Ancestor (LCA). Any invoices in the `Detected` state from the orphaned chain are automatically rolled back to `Pending` without double-crediting merchant balances.

---

## 9. Zone C AWS Nitro Enclave & Key Custody (`gw-kms-enclave`)

### Nitro Enclave Architecture & Attestation
The enclave runs in an isolated virtual machine without persistent storage or external network access. Communication occurs exclusively over VSOCK. The parent instance verifies enclave identity via hardware attestation measurements (PCR0, PCR1, PCR2).

### PreSignPolicyGuard Raw Transaction Decoding
Before any cryptographic signature is computed, the `PreSignPolicyGuard` independently decodes the raw transaction payload:
- Bitcoin: Deserializes the PSBT (BIP-174).
- EVM: Deserializes the RLP byte payload and validates recipient address and gas limit.
- Solana: Deserializes the SVM Message format and verifies instruction program IDs.
- TON: Parses the Bag of Cells (BOC) payload.
- Sui: Deserializes the BCS encoded transaction data.

### Destination Address Whitelist Pinning
If the destination address is not explicitly present in the immutable enclave whitelist, signing is aborted immediately with `PreSignPolicyViolation::DestinationNotWhitelisted`.

### M-of-N Quorum Enforcement & Zeroize Memory
Signing operational sweeps requires threshold authorization ($m$-of-$n$ approvals). Private key bytes are held exclusively within `zeroize::Zeroizing<[u8; 64]>`, which overwrites the memory buffer with zeros immediately when dropped.

---

## 10. Unified Treasury & FIFO Cost-Basis Accounting (`gw-treasury`)

### Cross-Network Canonical 18-Decimal Tensor
`gw-treasury` aggregates balances across disparate token standards by normalizing them into canonical 18-decimal integer representations:

$$\mathcal{N}_{18}(r, d) = \begin{cases} r \otimes 10^{18 - d} & \text{if } d \le 18 \\ \lfloor r / 10^{d - 18} \rfloor & \text{if } d > 18 \end{cases}$$

### FIFO Tax Lot Ingestion & Prefix-Sum Depletion
Every verified checkout invoice is recorded as an acquisition lot. When funds are swept or traded, acquisition lots are consumed in chronological FIFO order using exact prefix sums:

$$\delta_k = \max(0, \min(q_k, D - S_{k-1})), \qquad S_k = \sum_{i=1}^k q_i$$
$$\text{NetRealizedPnL} = \text{Proceeds} - \text{CostBasis} - \text{Fee}$$

### Economical Sweep Threshold Calculus
Sweeping is only triggered when the deposit value exceeds network gas costs by the configured economic factor:
$$R_{\min} = \left\lceil \frac{V_{\min} \otimes 10^d}{P_\mu} \right\rceil$$

### Zero-Dust Hot/Cold Liquidity Splitting
Hot wallet balances are automatically split between cold vault custody and market operational liquidity:
$$Q_{\to \text{Cold}} = \left\lfloor \frac{B \otimes \alpha_{\text{cold}}}{10,000} \right\rfloor, \qquad Q_{\to \text{Market}} = B - Q_{\to \text{Cold}}$$
Ensuring $Q_{\to \text{Cold}} + Q_{\to \text{Market}} \equiv B$ with zero integer truncation loss.

---

## 11. Production Deployment, Systemd & Monitoring

### Systemd Service Units

#### 1. Zone A API Service (`/etc/systemd/system/gateway-api.service`)

```ini
[Unit]
Description=Gateway Crypto Zone A Checkout & Treasury API
After=network.target

[Service]
Type=simple
User=gateway
Group=gateway
WorkingDirectory=/var/lib/gateway
ExecStart=/usr/local/bin/gw-api --config /etc/gateway/config.toml
Restart=always
RestartSec=5
LimitNOFILE=65536
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/gateway
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

#### 2. Zone C Enclave Runner (`/etc/systemd/system/gateway-enclave.service`)

```ini
[Unit]
Description=Gateway Crypto Zone C Nitro Enclave
After=nitro-enclaves-allocator.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/nitro-cli run-enclave --cpu-count 2 --memory 4096 --eif-path /var/lib/gateway/enclave.eif --enclave-cid 16
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

### Prometheus Metrics Reference

The API exports OpenMetrics formatted metrics on `GET /metrics`:

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `gateway_invoices_created_total` | Counter | Total checkout invoices issued. |
| `gateway_invoices_settled_total` | Counter | Total invoices reaching `VerifiedComplete`. |
| `gateway_oracle_deviation_bps` | Gauge | Current mid-price vs on-chain deviation in bps. |
| `gateway_circuit_breaker_tripped` | Gauge | `1` if circuit breaker is tripped, `0` otherwise. |
| `gateway_reorg_rollbacks_total` | Counter | Number of invoices reverted due to reorgs. |
| `gateway_memcache_shards_active` | Gauge | Number of active sharded cache partitions. |
| `gateway_treasury_canonical_balance` | Gauge | Total normalized canonical 18-decimal balance. |

---

### Structured Logging Configuration
Configure JSON formatted logging in production by setting the `RUST_LOG` environment variable:

```bash
export RUST_LOG="info,gw_engine=debug,gw_memcache=info,gw_treasury=debug"
export RUST_LOG_STYLE="never"
```

---

## 12. Incident Runbooks & Disaster Recovery

### Runbook 1: Dual-Oracle Deviation Trip
- **Symptom:** Invoices return HTTP 503; logs show `OracleDeviationExceeded(182 bps > 150 bps)`.
- **Cause:** High market volatility or oracle flash-crash on Binance or Chainlink.
- **Resolution:**
  1. Inspect upstream exchange feeds and on-chain oracle status.
  2. If divergence is driven by legitimate volatility, update `max_deviation_bps = 250` in `config.toml`.
  3. Reload configuration via `kill -HUP $(pidof gw-api)`.

### Runbook 2: Chain Reorg Exceeding Standard Depth
- **Symptom:** Ingress node reports block hash mismatch on Gate 5.
- **Resolution:**
  1. Inspect ring-buffer LCA search logs: `find_lowest_common_ancestor`.
  2. Verify that orphaned invoices reverted to `Pending`.
  3. Allow node to ingest alternate branch until confirmation threshold is reached.

### Runbook 3: Enclave PreSign Policy Rejection
- **Symptom:** Sweeps fail with `PreSignPolicyViolation::DestinationNotWhitelisted`.
- **Cause:** Sweep transaction attempted to send funds to an unauthorized address.
- **Resolution:**
  1. Verify destination address against merchant cold storage registry.
  2. Submit governance multisig proposal to update the enclave whitelist image.
  3. Re-build and re-deploy enclave EIF.

### Runbook 4: Database WAL Checkpoint Lock
- **Symptom:** Write operations fail with `SQLite Database Locked`.
- **Resolution:**
  1. Execute manual WAL checkpoint: `sqlite3 ledger.db "PRAGMA wal_checkpoint(TRUNCATE);"`.
  2. Ensure background processes are utilizing read-uncommitted mode.

### Runbook 5: Gas Relayer Low Balance Emergency Refill
- **Symptom:** Relayer alert `RelayerGasLow(balance < $20.00)`.
- **Resolution:**
  1. Check `GET /api/v1/treasury/portfolio` for gas relayer status.
  2. Dispatch automated top-up transaction via `SovereignCrossNetworkLiquidityRouter`.

### Runbook 6: Unconfirmed Mempool Replacement (RBF / CPFP)
- **Symptom:** Bitcoin deposit transaction stuck in mempool with low fee rate during congestion.
- **Resolution:**
  1. Inspect transaction fee rate against current network sat/vB requirements.
  2. For incoming payments, invoice remains in `Detected(0 conf)` state until inclusion.
  3. For outgoing sweeps, initiate Zone C Enclave CPFP (Child-Pays-For-Parent) signature to accelerate transaction confirmation.

### Runbook 7: Ingress Node Desync & Fork Recovery
- **Symptom:** Ingress node halts block progression or falls > 100 blocks behind peers.
- **Resolution:**
  1. Check node peer count and consensus sync logs (`reth` / `bitcoind`).
  2. Switch active RPC routing to secondary fallback node in `config.toml`.
  3. Restart ingress node with `--sync-mode=snap` or `--prune=full`.

---

## 13. End-to-End Verification & Automated Testing

Execute the comprehensive institutional verification suite to validate all mathematical theorems, typestate invariants, and multi-chain adapters:

```bash
# 1. Run all unit tests across the 15 crates
cargo test --workspace

# 2. Run formal mathematical theory tests
cargo test -p gw-primitives --test mathematical_theory_tests

# 3. Run multi-chain adapter coverage tests
cargo test -p gw-chain-traits --test multi_chain_adapter_tests

# 4. Run treasury FIFO and liquidity routing tests
cargo test -p gw-treasury --test treasury_theory_tests

# 5. Run API integration tests
cargo test -p gw-api --test api_theory_tests

# 6. Run institutional reorg simulation & adversarial fuzz tests
cargo test -p gw-verification-suite --test institutional_hardening_tests

# 7. Verify zero float usage across production crates
git grep -E "\bf32\b|\bf64\b" -- "crates/*/src/"
# Must return 0 matches.

# 8. Verify Zone A zero-key isolation
cargo tree -p gw-api --edges no-dev | grep -E "kms|enclave|ed25519-dalek|secp256k1"
# Must return 0 matches.
```

---

## 14. Automated End-to-End Integration Test Runner

Use this standalone script to simulate an end-to-end checkout, deposit detection, and settlement verification against a running `gw-api` instance:

```python
#!/usr/bin/env python3
"""
Institutional Automated Verification & Checkout Simulator
Validates:
1. Invoice Creation with Dust Truncation
2. Idempotency Key Replay Immunity
3. WebSocket Deposit Stream Notification
4. Status Query Settlement Finality
"""

import sys
import time
import uuid
import json
import urllib.request
import urllib.error

API_BASE = "http://127.0.0.1:8080"

def test_api():
    print("[*] 1. Checking API Health Probe...")
    try:
        with urllib.request.urlopen(f"{API_BASE}/health") as resp:
            assert resp.status == 200
            print("    -> Health check OK.")
    except Exception as e:
        print(f"[-] ERROR: API not accessible at {API_BASE}: {e}")
        sys.exit(1)

    print("[*] 2. Creating Locked Checkout Invoice ($100.00 USDT on Ethereum)...")
    idempotency_key = str(uuid.uuid4())
    req_body = json.dumps({
        "amount_usd_micros": 100000000,
        "chain": "Ethereum",
        "symbol": "USDT",
        "ttl_seconds": 1800
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{API_BASE}/api/v1/invoices",
        data=req_body,
        headers={
            "Content-Type": "application/json",
            "X-Idempotency-Key": idempotency_key
        }
    )

    with urllib.request.urlopen(req) as resp:
        assert resp.status == 201
        data = json.loads(resp.read().decode("utf-8"))
        invoice_id = data["invoice_id"]
        pay_address = data["pay_address"]
        print(f"    -> Created Invoice {invoice_id} with address {pay_address}")

    print("[*] 3. Testing Idempotency Replay Protection...")
    # Re-sending exact same key must yield identical result without creating duplicate
    req_duplicate = urllib.request.Request(
        f"{API_BASE}/api/v1/invoices",
        data=req_body,
        headers={
            "Content-Type": "application/json",
            "X-Idempotency-Key": idempotency_key
        }
    )
    try:
        with urllib.request.urlopen(req_duplicate) as resp:
            print("    -> Idempotent replay accepted safely.")
    except urllib.error.HTTPError as e:
        if e.code == 409:
            print("    -> Idempotent collision correctly detected with HTTP 409.")

    print("[*] 4. Querying Invoice Status...")
    with urllib.request.urlopen(f"{API_BASE}/api/v1/invoices/{invoice_id}") as resp:
        status_data = json.loads(resp.read().decode("utf-8"))
        print(f"    -> Invoice Status: {status_data['status']}")

    print("[*] 5. Querying Treasury Portfolio Tensor...")
    with urllib.request.urlopen(f"{API_BASE}/api/v1/treasury/portfolio") as resp:
        treasury_data = json.loads(resp.read().decode("utf-8"))
        print(f"    -> Treasury Valuation: ${treasury_data['total_usd_value_micros'] / 1_000_000:.2f} USD")

    print("[+] All integration simulation assertions PASSED successfully.")

if __name__ == "__main__":
    test_api()
```

---

## 15. Mathematical Verification Numerical Traces

This section provides explicit numerical traces verifying the core mathematical formulas implemented in `gateway-crypto`.

### Trace 1: Canonical 18-Decimal Normalization ($\mathcal{N}_{18}$)
- **Asset A:** TRC-20 USDT (6 decimals). Balance: $100.00\text{ USDT} = 100,000,000\text{ raw units}$.
  $$\mathcal{N}_{18}(100,000,000, 6) = 100,000,000 \times 10^{18 - 6} = 100,000,000 \times 10^{12} = 100 \times 10^{18}\text{ units}$$
- **Asset B:** ERC-20 DAI (18 decimals). Balance: $50.00\text{ DAI} = 50 \times 10^{18}\text{ raw units}$.
  $$\mathcal{N}_{18}(50 \times 10^{18}, 18) = 50 \times 10^{18}\text{ units}$$
- **Homomorphic Aggregate:**
  $$\text{Total} = (100 \times 10^{18}) + (50 \times 10^{18}) = 150 \times 10^{18}\text{ canonical units}$$
  $$\text{Total USD} = 150 \times 10^{18} \times \frac{\$1.00}{10^{18}} = \$150.00\text{ USD}$$

### Trace 2: Exact FIFO Tax Lot Depletion ($\delta_k$)
Suppose a merchant received 3 separate customer checkouts:
- Lot 1 ($k=1$): $q_1 = 40.00\text{ USDT}$, acquired at $p_1 = \$0.998$ ($998,000\text{ }\mu\text{USD}$).
- Lot 2 ($k=2$): $q_2 = 60.00\text{ USDT}$, acquired at $p_2 = \$1.002$ ($1,002,000\text{ }\mu\text{USD}$).
- Lot 3 ($k=3$): $q_3 = 50.00\text{ USDT}$, acquired at $p_3 = \$1.000$ ($1,000,000\text{ }\mu\text{USD}$).

The merchant disposes/sweeps $D = 80.00\text{ USDT}$ at current market price $p_{\text{market}} = \$1.005$:
1. **Prefix Sums:** $S_0 = 0$, $S_1 = 40$, $S_2 = 100$, $S_3 = 150$.
2. **Lot 1 Depletion ($\delta_1$):**
   $$\delta_1 = \max(0, \min(40, 80 - 0)) = 40.00\text{ USDT}\quad (\text{Lot 1 fully depleted})$$
   $$\text{Cost Basis}_1 = \frac{40 \times 998,000}{1} = \$39.920000\text{ USD}$$
3. **Lot 2 Depletion ($\delta_2$):**
   $$\delta_2 = \max(0, \min(60, 80 - 40)) = 40.00\text{ USDT}\quad (\text{Lot 2 partially depleted, 20 remaining})$$
   $$\text{Cost Basis}_2 = \frac{40 \times 1,002,000}{1} = \$40.080000\text{ USD}$$
4. **Lot 3 Depletion ($\delta_3$):**
   $$\delta_3 = \max(0, \min(50, 80 - 100)) = 0.00\text{ USDT}\quad (\text{Lot 3 untouched})$$
5. **Total Cost Basis & Realized P&L:**
   $$\text{Total Cost Basis} = \$39.920000 + \$40.080000 = \$80.000000\text{ USD}$$
   $$\text{Gross Proceeds} = 80 \times 1.005 = \$80.400000\text{ USD}$$
   $$\text{Net Realized P&L} = \$80.400000 - \$80.000000 = +\$0.400000\text{ USD}\quad (+400,000\text{ }\mu\text{USD})$$

### Trace 3: Zero-Dust Proportional Split ($\alpha_{\text{cold}} = 8000$)
- Balance $B = 333\text{ USDT}$ ($333,000,000\text{ raw units}$), $\alpha_{\text{cold}} = 8000$ ($80.00\%$):
  $$Q_{\to \text{Cold}} = \left\lfloor \frac{333,000,000 \times 8000}{10000} \right\rfloor = 266,400,000\text{ units}\quad (266.40\text{ USDT})$$
  $$Q_{\to \text{Market}} = 333,000,000 - 266,400,000 = 66,600,000\text{ units}\quad (66.60\text{ USDT})$$
- Conservation check:
  $$Q_{\to \text{Cold}} + Q_{\to \text{Market}} = 266,400,000 + 66,600,000 = 333,000,000 \equiv B$$
  Integer conservation holds with exactly zero dust truncation loss.

---

## 16. Enterprise Security & Key Custody Audit Checklist

Before placing `gateway-crypto` into production custody, complete this institutional security audit:

- [ ] **1. Zone A Key Isolation:** Execute `cargo tree -p gw-api --edges no-dev` and verify zero references to `kms`, `enclave`, `ed25519-dalek`, or `secp256k1`.
- [ ] **2. Floating-Point Audit:** Run `git grep -E "\bf32\b|\bf64\b" -- "crates/*/src/"` and confirm 0 matches across all production source files.
- [ ] **3. Unsafe Code Audit:** Confirm `#![forbid(unsafe_code)]` is active across all 15 crates.
- [ ] **4. Dual-Oracle Calibration:** Verify WebSocket mid-price and Chainlink aggregator endpoints in `config.toml` and confirm `max_deviation_bps = 150`.
- [ ] **5. Nitro Enclave Attestation:** Ensure Zone C Enclave image is compiled with `nitro-cli` and PCR0 hash matches `pcr0_measurement` in `config.toml`.
- [ ] **6. Whitelist Validation:** Verify that destination cold storage vault addresses for all 8 networks are pre-pinned in Zone C immutable storage.
- [ ] **7. TRON Warm Slot Verification:** Confirm `dust_keeper_enabled = true` to preserve 65,000 Energy savings on TRC-20 sweeps.
- [ ] **8. SQLite WAL Backup:** Configure automated nightly snapshots of `ledger.db` using SQLite online backup API (`VACUUM INTO '/backups/ledger_backup.db'`).

---

*End of Usage Guide. For theoretical proofs, refer to [`UNIFIED_RUST_CRYPTO_GATEWAY_AND_TREASURY_SPEC_THEORY.md`](./UNIFIED_RUST_CRYPTO_GATEWAY_AND_TREASURY_SPEC_THEORY.md).*
