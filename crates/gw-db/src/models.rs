//! # SQLite Relational Ledger Models
//!
//! Strongly typed schema definitions using `oberer-orm` for pure-Rust SQLite ORM mapping.

#![allow(missing_docs)]

use oberer_orm_derive::OrmTable;
use serde::{Deserialize, Serialize};

/// Supported physical token contracts and native assets.
#[derive(OrmTable, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportedAssetRecord {
    /// Internal primary key.
    #[orm(primary_key, auto_increment)]
    pub id: i64,
    /// Chain ID (0: BTC, 1: ETH, 56: BNB, 98866: Plume, 900: Solana, 728126428: Tron, 1100: TON, 1200: Sui).
    pub chain_id: i64,
    /// High-level logical asset code (BTC, ETH, SOL, USDT, etc.).
    pub logical_asset: String,
    /// Canonical contract address, mint address, or `"NATIVE"`.
    pub token_contract: String,
    /// Decimal precision on-chain.
    pub decimals: i64,
    /// True if sweeps must leave 1 raw unit of dust (e.g. TRC-20 warm slot).
    pub keep_one_unit_dust: bool,
    /// Required confirmation depth.
    pub target_confirmations: i64,
    /// Whether this asset is actively enabled for checkouts.
    pub is_active: bool,
}

/// Rotating guest deposit address pool for CREATE2 proxies and pre-computed salts.
#[derive(OrmTable, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositAddressPoolRecord {
    /// Internal primary key.
    #[orm(primary_key, auto_increment)]
    pub id: i64,
    /// Target blockchain network ID.
    pub chain_id: i64,
    /// Derived receiving address.
    pub deposit_address: String,
    /// Optional secondary reference (Solana Reference Pubkey or TON Memo).
    pub routing_reference: Option<String>,
    /// Derivation locator or CREATE2 salt.
    pub derivation_locator: String,
    /// Lease status: "AVAILABLE", "LEASED", "COOLDOWN".
    pub lease_status: String,
    /// Unix timestamp when lease or cooldown expires.
    pub leased_until_unix: i64,
}

/// Customer checkout invoice record with compile-time typestate lifecycle tracking.
#[derive(OrmTable, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceRecord {
    /// Internal primary key (used as `invoice_id` in `gw-memcache`).
    #[orm(primary_key, auto_increment)]
    pub id: i64,
    /// Unique public UUID for the checkout session.
    pub invoice_uuid: String,
    /// Target blockchain network.
    pub chain_id: i64,
    /// Logical asset expected.
    pub logical_asset: String,
    /// Primary deposit address.
    pub deposit_address: String,
    /// Optional secondary routing key (Solana ref pubkey or TON memo).
    pub routing_reference: Option<String>,
    /// Expected payment amount encoded as fixed-point decimal integer string.
    pub expected_amount_raw: String,
    /// Expected decimal precision scale.
    pub expected_amount_decimals: i64,
    /// Locked USD valuation in micros ($10^{-6}\text{ USD}$).
    pub locked_usd_micros: i64,
    /// Lifecycle status: "PENDING", "DETECTED", "PARTIAL", "VERIFIED_COMPLETE", "EXPIRED".
    pub status: String,
    /// First detected transaction hash.
    pub detected_tx_hash: Option<String>,
    /// Total cumulative raw amount received.
    pub received_amount_raw: String,
    /// Unix timestamp of creation.
    pub created_at_unix: i64,
    /// Monotonic expiration timestamp.
    pub expires_at_unix: i64,
    /// Timestamp when invoice was verified and settled.
    pub settled_at_unix: Option<i64>,
}

/// Treasury vault wallet record across security tiers.
#[derive(OrmTable, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryWalletRecord {
    /// Internal primary key.
    #[orm(primary_key, auto_increment)]
    pub id: i64,
    /// Target blockchain network ID.
    pub chain_id: i64,
    /// Wallet security tier ("Tier0CustomerDeposit", "Tier1GasRelayer", "Tier2OperationalHot", "Tier3ColdVault", "Tier4MarketExchange").
    pub wallet_tier: String,
    /// Wallet address on-chain.
    pub address: String,
    /// Key locator or HSM path identifier.
    pub key_locator: String,
    /// Whether this wallet is currently active.
    pub is_active: bool,
}

/// FIFO cost-basis tax lot record for real-time asset accounting.
#[derive(OrmTable, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostBasisLotRecord {
    /// Internal primary key.
    #[orm(primary_key, auto_increment)]
    pub id: i64,
    /// Unique tax lot UUID.
    pub lot_uuid: String,
    /// Originating invoice ID if acquired via customer checkout.
    pub invoice_id: Option<i64>,
    /// Originating blockchain network ID.
    pub chain_id: i64,
    /// Logical asset symbol.
    pub logical_asset: String,
    /// Physical token contract address.
    pub token_contract: String,
    /// Initial acquired raw amount string.
    pub original_amount_raw: String,
    /// Remaining unconsumed raw amount string.
    pub remaining_amount_raw: String,
    /// Decimal precision scale.
    pub decimals: i64,
    /// Locked USD acquisition price in micros ($10^{-6}\text{ USD}$).
    pub usd_price_micros: i64,
    /// Acquisition timestamp in Unix seconds.
    pub acquired_at_unix: i64,
    /// True once the remaining balance is completely depleted via FIFO.
    pub is_exhausted: bool,
}

/// Realized Profit & Loss ledger record generated upon FIFO lot disposal.
#[derive(OrmTable, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealizedPnlRecord {
    /// Internal primary key.
    #[orm(primary_key, auto_increment)]
    pub id: i64,
    /// Unique disposal UUID.
    pub disposal_uuid: String,
    /// Associated cost-basis lot ID.
    pub lot_id: i64,
    /// Logical asset symbol.
    pub logical_asset: String,
    /// Raw amount disposed.
    pub disposed_amount_raw: String,
    /// Unit acquisition price in USD micros.
    pub acquisition_price_micros: i64,
    /// Unit disposal price in USD micros.
    pub disposal_price_micros: i64,
    /// Realized P&L in USD micros (positive = gain, negative = loss).
    pub realized_pnl_micros: i64,
    /// Disposal timestamp in Unix seconds.
    pub disposed_at_unix: i64,
}
