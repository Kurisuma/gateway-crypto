//! # gw-primitives
//!
//! Sovereign foundational domain primitives, fixed-point integer types,
//! taxonomic network/asset identifiers, and the canonical error model for
//! the Unified Crypto Gateway & Treasury architecture.
//!
//! # Security & Mathematical Invariants
//! - `#![forbid(unsafe_code)]`: Absolute memory safety guaranteed at compile time.
//! - Pure integer arithmetic: Floating point operations (`f32`/`f64`) are strictly forbidden.
//! - Precision-safe token amounts: Enforces matching decimal scales for on-chain arithmetic,
//!   or explicit canonical 18-decimal homomorphism $\mathcal{N}_{18}(r, d)$.

#![forbid(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
#![warn(missing_docs)]

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Exhaustive error model for foundational mathematical, taxonomic, and integrity invariants.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SovereignError {
    /// Integer arithmetic overflow occurred in fixed-point BigInt computation.
    #[error("Arithmetic overflow in BigInt calculation: {context}")]
    Overflow {
        /// Operational context or function name where overflow occurred.
        context: &'static str,
    },

    /// Integer arithmetic underflow occurred in fixed-point BigInt computation.
    #[error("Arithmetic underflow in BigInt calculation: {context}")]
    Underflow {
        /// Operational context or function name where underflow occurred.
        context: &'static str,
    },

    /// Division by zero attempted during pricing, quota, or P&L calculations.
    #[error("Division by zero in pricing or fixed-point integer calculation")]
    DivisionByZero,

    /// Mismatched token decimal precision preventing direct raw integer arithmetic.
    #[error("Asset decimal scale mismatch: expected {expected}, actual {actual}")]
    DecimalMismatch {
        /// Expected scale.
        expected: u8,
        /// Actual scale provided.
        actual: u8,
    },

    /// Mismatched logical assets in single-currency arithmetic operation.
    #[error("Logical asset mismatch: expected {expected:?}, actual {actual:?}")]
    LogicalAssetMismatch {
        /// Expected logical asset.
        expected: LogicalAsset,
        /// Actual logical asset provided.
        actual: LogicalAsset,
    },

    /// Dual-oracle price divergence exceeded maximum allowed basis points threshold.
    #[error(
        "Dual-oracle divergence circuit breaker tripped: cex_mid={cex_mid}, onchain={onchain}, divergence_bps={divergence_bps} > max_bps={max_bps}"
    )]
    OracleDivergenceCircuitBreaker {
        /// CEX orderbook mid-price in USD micros.
        cex_mid: u128,
        /// On-chain oracle price in USD micros.
        onchain: u128,
        /// Computed divergence in basis points (1 bps = 0.01%).
        divergence_bps: u32,
        /// Maximum allowed divergence threshold in basis points.
        max_bps: u32,
    },

    /// Invalid basis points argument (must be <= 10,000 for standard ratios).
    #[error("Invalid basis points tolerance value: {0}")]
    InvalidBpsTolerance(u16),

    /// Invalid cryptographic or checksum address representation.
    #[error("Invalid blockchain address or token contract format: {0}")]
    InvalidAddressFormat(String),

    /// Formatting error when serializing clean display strings.
    #[error("Display string formatting error: {0}")]
    FormattingError(String),

    /// General invariant violation or unclassified domain error.
    #[error("Domain invariant violation: {0}")]
    General(String),
}

/// Canonical logical assets supported across all integrated blockchain networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LogicalAsset {
    /// Bitcoin (Native BTC)
    Btc,
    /// Ethereum (Native ETH)
    Eth,
    /// BNB Chain (Native BNB)
    Bnb,
    /// Plume Network (Native PLUME)
    Plume,
    /// Solana (Native SOL)
    Sol,
    /// TRON (Native TRX)
    Trx,
    /// The Open Network (Native TON)
    Ton,
    /// Sui Network (Native SUI)
    Sui,
    /// Tether USD (USDT across EVM, TRC-20, Solana SPL, TON Jetton)
    Usdt,
    /// USD Coin (USDC across EVM, Solana SPL, Sui)
    Usdc,
    /// Plume USD (USDP)
    Usdp,
}

impl LogicalAsset {
    /// Indicates whether the logical asset represents a USD-pegged stablecoin.
    pub const fn is_stablecoin(self) -> bool {
        matches!(self, Self::Usdt | Self::Usdc | Self::Usdp)
    }

    /// Default base decimal precision for the native asset on its home network.
    pub const fn default_decimals(self) -> u8 {
        match self {
            Self::Btc => 8,
            Self::Eth | Self::Bnb | Self::Plume => 18,
            Self::Sol | Self::Ton | Self::Sui => 9,
            Self::Trx | Self::Usdt | Self::Usdc | Self::Usdp => 6,
        }
    }
}

impl fmt::Display for LogicalAsset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Btc => write!(f, "BTC"),
            Self::Eth => write!(f, "ETH"),
            Self::Bnb => write!(f, "BNB"),
            Self::Plume => write!(f, "PLUME"),
            Self::Sol => write!(f, "SOL"),
            Self::Trx => write!(f, "TRX"),
            Self::Ton => write!(f, "TON"),
            Self::Sui => write!(f, "SUI"),
            Self::Usdt => write!(f, "USDT"),
            Self::Usdc => write!(f, "USDC"),
            Self::Usdp => write!(f, "USDP"),
        }
    }
}

/// Core execution architecture taxonomy for multi-network adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainArchitecture {
    /// Bitcoin UTXO model with BIP-84/PSBT mechanics.
    BitcoinUtxo,
    /// EVM account-based model with CREATE2 counterfactual proxies.
    EvmAccount,
    /// Solana SVM account model with Reference Pubkeys and PDAs.
    SvmAccount,
    /// TRON TVM account model with Base58 CREATE2 and Stake 2.0.
    TvmAccount,
    /// TON Actor model with Jetton notifications and Crockford Base32 memos.
    TonActor,
    /// Sui Move object model with programmable transaction blocks (PTB).
    MoveObject,
}

/// Unique canonical chain identifier across both EVM and non-EVM networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u64)]
pub enum ChainId {
    /// Bitcoin Mainnet (BIP-84 native SegWit)
    BitcoinMainnet = 0,
    /// Ethereum Mainnet (Chain ID 1)
    EthereumMainnet = 1,
    /// BNB Smart Chain (Chain ID 56)
    BnbChain = 56,
    /// Plume Mainnet (Chain ID 98866)
    PlumeMainnet = 98866,
    /// Solana Mainnet-Beta (Internal ID 900)
    SolanaMainnet = 900,
    /// TRON Mainnet (Chain ID 728126428)
    TronMainnet = 728126428,
    /// The Open Network Mainnet (Internal ID 1100)
    TonMainnet = 1100,
    /// Sui Mainnet (Internal ID 1200)
    SuiMainnet = 1200,
}

impl ChainId {
    /// Returns the underlying execution architecture for this blockchain network.
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

    /// Numeric representation of the chain ID.
    pub const fn as_u64(self) -> u64 {
        self as u64
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BitcoinMainnet => write!(f, "Bitcoin Mainnet (0)"),
            Self::EthereumMainnet => write!(f, "Ethereum Mainnet (1)"),
            Self::BnbChain => write!(f, "BNB Smart Chain (56)"),
            Self::PlumeMainnet => write!(f, "Plume Mainnet (98866)"),
            Self::SolanaMainnet => write!(f, "Solana Mainnet (900)"),
            Self::TronMainnet => write!(f, "TRON Mainnet (728126428)"),
            Self::TonMainnet => write!(f, "TON Mainnet (1100)"),
            Self::SuiMainnet => write!(f, "Sui Mainnet (1200)"),
        }
    }
}

/// Identifies a concrete physical token contract or native gas asset on a specific chain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PhysicalAssetId {
    /// Target blockchain network.
    pub chain_id: ChainId,
    /// High-level logical asset.
    pub logical_asset: LogicalAsset,
    /// Canonical lowercase contract address, mint address, or `"NATIVE"` for base gas coins.
    pub token_contract: String,
    /// On-chain decimal precision.
    pub decimals: u8,
    /// If true, sweeps must leave 1 raw unit of dust behind (e.g. TRON TRC-20 warm slot preservation).
    pub keep_one_unit_dust: bool,
    /// Number of block confirmations required before reaching finality.
    pub target_confirmations: u32,
}

/// Wallet security tier taxonomy for zero-trust key isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WalletTier {
    /// Ephemeral Tier 0: Customer deposit routes (CREATE2 proxies, BTC zpub, Solana reference/PDA).
    Tier0CustomerDeposit,
    /// Tier 1: Gas Relayer (<$2,000 native coin budget, Tron Stake 2.0 Energy).
    Tier1GasRelayer,
    /// Tier 2: Operational Hot Vault (MPC 2-of-2 / automated policy-gated).
    Tier2OperationalHot,
    /// Tier 3: Cold Vault (Air-gapped 3-of-5 hardware multi-sig).
    Tier3ColdVault,
    /// Tier 4: Institutional Exchange (Prime brokerage/liquidity venue).
    Tier4MarketExchange,
}

impl fmt::Display for WalletTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tier0CustomerDeposit => write!(f, "Tier 0 (Customer Deposit)"),
            Self::Tier1GasRelayer => write!(f, "Tier 1 (Gas Relayer)"),
            Self::Tier2OperationalHot => write!(f, "Tier 2 (Operational Hot)"),
            Self::Tier3ColdVault => write!(f, "Tier 3 (Cold Vault)"),
            Self::Tier4MarketExchange => write!(f, "Tier 4 (Market Exchange)"),
        }
    }
}

/// In-Memory Priority-Redundant Cache Engine (IMPRCE) priority tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CachePriorityTier {
    /// P0: Immortal consensus roots, contract whitelists ($k=3$ replication).
    P0CriticalConsensus,
    /// P1: Active checkout deposit watchlist ($k=3$ replication).
    P1ActivePaymentWatch,
    /// P2: Rotating pool leases in cooldown ($k=2$ replication).
    P2PoolLeaseCooldown,
    /// P3: Locked price quotes & oracle rates ($k=2$ replication).
    P3OracleQuoteLock,
    /// P4: Ephemeral idempotency & telemetry ($k=1$ replication).
    P4TelemetryIdempotency,
}

impl CachePriorityTier {
    /// Hardware mirror arena replication factor $k$.
    pub const fn replication_factor(self) -> usize {
        match self {
            Self::P0CriticalConsensus | Self::P1ActivePaymentWatch => 3,
            Self::P2PoolLeaseCooldown | Self::P3OracleQuoteLock => 2,
            Self::P4TelemetryIdempotency => 1,
        }
    }

    /// Whether entries in this tier are pinned and immune to capacity eviction before expiry.
    pub const fn is_pinned_until_expiry(self) -> bool {
        matches!(
            self,
            Self::P0CriticalConsensus | Self::P1ActivePaymentWatch | Self::P2PoolLeaseCooldown
        )
    }

    /// Base weight $\omega(p)$ utilized in the retention priority scoring function $\Phi$.
    pub const fn base_weight(self) -> u64 {
        match self {
            Self::P0CriticalConsensus => 1_000_000_000,
            Self::P1ActivePaymentWatch => 100_000_000,
            Self::P2PoolLeaseCooldown => 10_000_000,
            Self::P3OracleQuoteLock => 1_000_000,
            Self::P4TelemetryIdempotency => 1,
        }
    }
}

/// Precision-safe on-chain token amount encapsulating the raw integer and decimal scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RawAssetAmount {
    raw: U256,
    decimals: u8,
}

impl RawAssetAmount {
    /// Constructs a new verified `RawAssetAmount`.
    pub const fn new(raw: U256, decimals: u8) -> Self {
        Self { raw, decimals }
    }

    /// Constructs a zero balance for the given decimal precision.
    pub const fn zero(decimals: u8) -> Self {
        Self {
            raw: U256::ZERO,
            decimals,
        }
    }

    /// Raw 256-bit unsigned integer value.
    pub const fn raw(&self) -> U256 {
        self.raw
    }

    /// On-chain decimal scale.
    pub const fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Returns `true` if the balance is exactly zero.
    pub fn is_zero(&self) -> bool {
        self.raw.is_zero()
    }

    /// Checked addition enforcing identical decimal scales.
    pub fn checked_add(self, rhs: Self) -> Result<Self, SovereignError> {
        if self.decimals != rhs.decimals {
            return Err(SovereignError::DecimalMismatch {
                expected: self.decimals,
                actual: rhs.decimals,
            });
        }
        let sum = self
            .raw
            .checked_add(rhs.raw)
            .ok_or(SovereignError::Overflow {
                context: "RawAssetAmount::checked_add",
            })?;
        Ok(Self::new(sum, self.decimals))
    }

    /// Checked subtraction enforcing identical decimal scales.
    pub fn checked_sub(self, rhs: Self) -> Result<Self, SovereignError> {
        if self.decimals != rhs.decimals {
            return Err(SovereignError::DecimalMismatch {
                expected: self.decimals,
                actual: rhs.decimals,
            });
        }
        let diff = self
            .raw
            .checked_sub(rhs.raw)
            .ok_or(SovereignError::Underflow {
                context: "RawAssetAmount::checked_sub",
            })?;
        Ok(Self::new(diff, self.decimals))
    }

    /// Multiplies the raw balance by basis points (1 bps = 0.01% = 1/10,000).
    pub fn checked_mul_bps(self, bps: u16) -> Result<Self, SovereignError> {
        let scaled = self
            .raw
            .checked_mul(U256::from(bps))
            .ok_or(SovereignError::Overflow {
                context: "RawAssetAmount::checked_mul_bps",
            })?
            .checked_div(U256::from(10_000_u64))
            .ok_or(SovereignError::DivisionByZero)?;
        Ok(Self::new(scaled, self.decimals))
    }

    /// Normalizes any token amount ($d \in [0, 36]$) into canonical 18-decimal integer units $\mathcal{N}_{18}(r, d)$.
    pub fn to_canonical_18(self) -> Result<U256, SovereignError> {
        if self.decimals == 18 {
            return Ok(self.raw);
        }
        if self.decimals < 18 {
            let exp = 18_u8
                .checked_sub(self.decimals)
                .ok_or(SovereignError::Underflow {
                    context: "to_canonical_18::exp_lt",
                })?;
            let factor = U256::from(10_u64)
                .checked_pow(U256::from(exp))
                .ok_or(SovereignError::Overflow {
                    context: "to_canonical_18::pow_lt",
                })?;
            self.raw.checked_mul(factor).ok_or(SovereignError::Overflow {
                context: "to_canonical_18::mul",
            })
        } else {
            let exp = self
                .decimals
                .checked_sub(18_u8)
                .ok_or(SovereignError::Underflow {
                    context: "to_canonical_18::exp_gt",
                })?;
            let divisor = U256::from(10_u64)
                .checked_pow(U256::from(exp))
                .ok_or(SovereignError::Overflow {
                    context: "to_canonical_18::pow_gt",
                })?;
            self.raw
                .checked_div(divisor)
                .ok_or(SovereignError::DivisionByZero)
        }
    }

    /// Backward-compatible alias for `to_canonical_18`.
    pub fn to_canonical_18_decimals(self) -> Result<U256, SovereignError> {
        self.to_canonical_18()
    }

    /// Formats the raw integer into a human-readable decimal string without floating-point math.
    pub fn to_clean_display_string(&self) -> Result<String, SovereignError> {
        if self.decimals == 0 {
            return Ok(self.raw.to_string());
        }

        let scale = U256::from(10_u64)
            .checked_pow(U256::from(self.decimals))
            .ok_or(SovereignError::Overflow {
                context: "to_clean_display_string::scale",
            })?;
        let whole = self
            .raw
            .checked_div(scale)
            .ok_or(SovereignError::DivisionByZero)?;
        let rem = self
            .raw
            .checked_rem(scale)
            .ok_or(SovereignError::DivisionByZero)?;

        if rem.is_zero() {
            return Ok(format!("{whole}.00"));
        }

        let width = usize::from(self.decimals);
        let rem_str = rem.to_string();
        let leading_zeroes = width.checked_sub(rem_str.len()).ok_or(SovereignError::Underflow {
            context: "to_clean_display_string::padding",
        })?;

        let mut frac = String::with_capacity(width);
        for _ in 0..leading_zeroes {
            frac.push('0');
        }
        frac.push_str(&rem_str);

        let trimmed = frac.trim_end_matches('0');
        if trimmed.is_empty() {
            Ok(format!("{whole}.00"))
        } else {
            Ok(format!("{whole}.{trimmed}"))
        }
    }
}

/// Fixed-point USD valuation scaled by $10^6$ (1 USD = 1,000,000 micros).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UsdMicros(pub u128);

impl UsdMicros {
    /// 1 USD represented in micro-units ($1,000,000$).
    pub const SCALE: u128 = 1_000_000;
    /// Constant for 1.00 USD.
    pub const ONE_USD: u128 = 1_000_000;

    /// Checked addition of two USD micro amounts.
    pub fn checked_add(self, rhs: Self) -> Result<Self, SovereignError> {
        self.0
            .checked_add(rhs.0)
            .map(Self)
            .ok_or(SovereignError::Overflow {
                context: "UsdMicros::checked_add",
            })
    }

    /// Checked subtraction of two USD micro amounts.
    pub fn checked_sub(self, rhs: Self) -> Result<Self, SovereignError> {
        self.0
            .checked_sub(rhs.0)
            .map(Self)
            .ok_or(SovereignError::Underflow {
                context: "UsdMicros::checked_sub",
            })
    }

    /// Evaluates divergence between CEX and on-chain oracle feeds.
    /// Returns the more conservative (lower) price if divergence $\le \text{max\_divergence\_bps}$.
    pub fn verify_dual_oracle_price(
        cex_mid_price: Self,
        onchain_oracle_price: Self,
        max_divergence_bps: u32,
    ) -> Result<Self, SovereignError> {
        let min_p = cex_mid_price.0.min(onchain_oracle_price.0);
        if min_p == 0 {
            return Err(SovereignError::DivisionByZero);
        }
        let abs_diff = cex_mid_price.0.abs_diff(onchain_oracle_price.0);
        let divergence_u128 = abs_diff
            .checked_mul(10_000)
            .ok_or(SovereignError::Overflow {
                context: "verify_dual_oracle_price::mul",
            })?
            .checked_div(min_p)
            .ok_or(SovereignError::DivisionByZero)?;

        let divergence_bps: u32 =
            u32::try_from(divergence_u128).map_err(|_| SovereignError::Overflow {
                context: "verify_dual_oracle_price::divergence_cast",
            })?;

        if divergence_bps > max_divergence_bps {
            return Err(SovereignError::OracleDivergenceCircuitBreaker {
                cex_mid: cex_mid_price.0,
                onchain: onchain_oracle_price.0,
                divergence_bps,
                max_bps: max_divergence_bps,
            });
        }

        // Return conservative minimum price to protect treasury
        Ok(Self(min_p))
    }

    /// Converts a fiat USD micro amount into raw blockchain units at a locked USD micro price.
    /// Trailing 12 noisy digits on 18-decimal tokens are truncated so customers receive a clean figure.
    pub fn to_locked_quote_raw(
        self,
        asset_price_usd_micros: Self,
        decimals: u8,
    ) -> Result<RawAssetAmount, SovereignError> {
        if asset_price_usd_micros.0 == 0 {
            return Err(SovereignError::DivisionByZero);
        }

        let scale_factor = U256::from(10_u64)
            .checked_pow(U256::from(decimals))
            .ok_or(SovereignError::Overflow {
                context: "to_locked_quote_raw::scale",
            })?;

        let numerator = U256::from(self.0)
            .checked_mul(scale_factor)
            .ok_or(SovereignError::Overflow {
                context: "to_locked_quote_raw::numerator",
            })?;

        let mut raw_amount = numerator
            .checked_div(U256::from(asset_price_usd_micros.0))
            .ok_or(SovereignError::DivisionByZero)?;

        // UX Clean Quote: Truncate bottom 12 digits on 18-decimal assets
        if decimals == 18 {
            let dust_mask = U256::from(1_000_000_000_000_u64); // 10^12
            raw_amount = raw_amount
                .checked_div(dust_mask)
                .ok_or(SovereignError::DivisionByZero)?
                .checked_mul(dust_mask)
                .ok_or(SovereignError::Overflow {
                    context: "to_locked_quote_raw::dust_mask_mul",
                })?;
        }

        Ok(RawAssetAmount::new(raw_amount, decimals))
    }

    /// Computes the USD micro valuation of a raw token balance at a given unit price.
    pub fn from_raw_asset_amount(
        amount: RawAssetAmount,
        asset_price_usd_micros: Self,
    ) -> Result<Self, SovereignError> {
        let scale_factor = U256::from(10_u64)
            .checked_pow(U256::from(amount.decimals()))
            .ok_or(SovereignError::Overflow {
                context: "from_raw_asset_amount::scale",
            })?;

        let usd_u256 = amount
            .raw()
            .checked_mul(U256::from(asset_price_usd_micros.0))
            .ok_or(SovereignError::Overflow {
                context: "from_raw_asset_amount::mul",
            })?
            .checked_div(scale_factor)
            .ok_or(SovereignError::DivisionByZero)?;

        let usd_u128 = u128::try_from(usd_u256).map_err(|_| SovereignError::Overflow {
            context: "from_raw_asset_amount::cast",
        })?;

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_asset_amount_checked_add_and_sub() {
        let a = RawAssetAmount::new(U256::from(1_000_000_u64), 6);
        let b = RawAssetAmount::new(U256::from(500_000_u64), 6);
        let sum = a.checked_add(b).expect("addition should succeed");
        assert_eq!(sum.raw(), U256::from(1_500_000_u64));

        let diff = a.checked_sub(b).expect("subtraction should succeed");
        assert_eq!(diff.raw(), U256::from(500_000_u64));

        // Decimal mismatch
        let c = RawAssetAmount::new(U256::from(1_000_000_u64), 8);
        assert!(matches!(
            a.checked_add(c),
            Err(SovereignError::DecimalMismatch { .. })
        ));
    }

    #[test]
    fn test_canonical_18_decimal_normalization() {
        // 1.5 USDT (6 decimals) = 1_500_000
        let usdt = RawAssetAmount::new(U256::from(1_500_000_u64), 6);
        let canonical = usdt.to_canonical_18().expect("normalization to 18 decimals");
        // 1.5 * 10^18 = 1_500_000_000_000_000_000
        assert_eq!(
            canonical,
            U256::from(1_500_000_000_000_000_000_u128)
        );

        // Native ETH (18 decimals) remains exact
        let eth = RawAssetAmount::new(U256::from(1_000_000_000_000_000_000_u128), 18);
        assert_eq!(
            eth.to_canonical_18().expect("exact 18 decimals"),
            U256::from(1_000_000_000_000_000_000_u128)
        );
    }

    #[test]
    fn test_clean_display_string() {
        let amt1 = RawAssetAmount::new(U256::from(100_500_000_u64), 6); // 100.5
        assert_eq!(amt1.to_clean_display_string().unwrap(), "100.5");

        let amt2 = RawAssetAmount::new(U256::from(100_000_000_u64), 6); // 100.00
        assert_eq!(amt2.to_clean_display_string().unwrap(), "100.00");

        let amt3 = RawAssetAmount::new(U256::from(5_000_000_u64), 8); // 0.05 BTC
        assert_eq!(amt3.to_clean_display_string().unwrap(), "0.05");
    }

    #[test]
    fn test_usd_micros_to_locked_quote_and_dust_truncation() {
        // $100.00 checkout invoice
        let invoice_usd = UsdMicros(100 * UsdMicros::SCALE);
        // ETH price = $2,500.00 -> 2,500_000_000 micros
        let eth_price = UsdMicros(2_500 * UsdMicros::SCALE);

        // 100 / 2500 = 0.04 ETH (18 decimals)
        let quote = invoice_usd
            .to_locked_quote_raw(eth_price, 18)
            .expect("valid quote");
        assert_eq!(quote.decimals(), 18);

        // 0.04 ETH = 40_000_000_000_000_000 raw
        assert_eq!(quote.raw(), U256::from(40_000_000_000_000_000_u64));
        assert_eq!(quote.to_clean_display_string().unwrap(), "0.04");
    }

    #[test]
    fn test_dual_oracle_deviation_circuit_breaker() {
        let p_cex = UsdMicros(2_000 * UsdMicros::SCALE);
        // Divergence = 1% = 100 bps (<= 150 bps allowed)
        let p_chain_normal = UsdMicros(2_020 * UsdMicros::SCALE);
        let accepted = UsdMicros::verify_dual_oracle_price(p_cex, p_chain_normal, 150)
            .expect("should pass within tolerance");
        assert_eq!(accepted, p_cex); // conservative minimum

        // Divergence = 2% = 200 bps (> 150 bps allowed) -> trip circuit breaker
        let p_chain_divergent = UsdMicros(2_040 * UsdMicros::SCALE);
        let err = UsdMicros::verify_dual_oracle_price(p_cex, p_chain_divergent, 150)
            .expect_err("should trip circuit breaker");
        assert!(matches!(
            err,
            SovereignError::OracleDivergenceCircuitBreaker { .. }
        ));
    }
}
