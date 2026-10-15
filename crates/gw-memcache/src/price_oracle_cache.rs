//! # Dual-Tier Price Quote & Oracle Circuit-Breaker Cache
//!
//! Enforces a strict 10-second monotonic TTL on real-time quotes streamed from centralized
//! WebSockets and performs automated cross-verification against on-chain Chainlink / Pyth oracles.

#![forbid(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
#![warn(missing_docs)]

use crate::sharded_engine::ShardedEnterpriseCache;
use crate::traits::{AdmissionPriority, CacheError, EnterpriseSecureCache, SecureCacheValue};
use gw_primitives::{LogicalAsset, UsdMicros};
use std::time::Duration;
use zeroize::Zeroize;

/// Wrapper around `LogicalAsset` providing zeroization and Blake3 serialization for cache keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CachedAsset(pub LogicalAsset);

impl Zeroize for CachedAsset {
    fn zeroize(&mut self) {
        self.0 = LogicalAsset::Usdt;
    }
}

impl SecureCacheValue for CachedAsset {
    fn update_mac_hasher(&self, hasher: &mut blake3::Hasher) {
        let discriminant = self.0 as u8;
        hasher.update(&[discriminant]);
    }
}

/// Dual-verified price quote binding real-time WebSocket mid-price with on-chain oracle verification.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DualVerifiedQuote {
    /// CEX WebSocket mid-price in USD micros.
    pub websocket_mid_usd: UsdMicros,
    /// On-chain oracle price in USD micros.
    pub onchain_oracle_usd: UsdMicros,
    /// Maximum allowed deviation tolerance in basis points.
    pub max_allowed_deviation_bps: u16,
}

impl Zeroize for DualVerifiedQuote {
    fn zeroize(&mut self) {
        self.websocket_mid_usd.0.zeroize();
        self.onchain_oracle_usd.0.zeroize();
        self.max_allowed_deviation_bps.zeroize();
    }
}

impl SecureCacheValue for DualVerifiedQuote {
    fn update_mac_hasher(&self, hasher: &mut blake3::Hasher) {
        hasher.update(&self.websocket_mid_usd.0.to_le_bytes());
        hasher.update(&self.onchain_oracle_usd.0.to_le_bytes());
        hasher.update(&self.max_allowed_deviation_bps.to_le_bytes());
    }
}

/// Hardened 10-Second TTL Price Cache with On-Chain Oracle Deviation Circuit Breaker.
pub struct PriceQuoteOracleCache {
    store: ShardedEnterpriseCache<CachedAsset, DualVerifiedQuote>,
    strict_ws_ttl: Duration,
}

impl PriceQuoteOracleCache {
    /// Creates a new price oracle cache with a 10-second monotonic TTL.
    pub fn new(csprng_seed: &[u8; 64]) -> Self {
        Self {
            store: ShardedEnterpriseCache::new(csprng_seed, b"GW_PRICE_ORACLE!", 256),
            strict_ws_ttl: Duration::from_secs(10), // Strict 10-second TTL
        }
    }

    /// Validates that the WebSocket price and on-chain oracle price agree within `max_deviation_bps`
    /// before sealing the quote into the 10-second monotonic cache.
    pub fn update_verified_quote(
        &self,
        asset: LogicalAsset,
        ws_price: UsdMicros,
        oracle_price: UsdMicros,
        max_deviation_bps: u16,
    ) -> Result<(), CacheError> {
        let diff = ws_price.0.abs_diff(oracle_price.0);
        let max_bps_u128 = u128::from(max_deviation_bps);
        let max_allowed_diff = oracle_price
            .0
            .saturating_mul(max_bps_u128)
            .checked_div(10_000)
            .unwrap_or(0);

        if diff > max_allowed_diff {
            // Immediately purge any cached price for this asset so stale prices cannot be used
            self.store.remove_and_zeroize(&CachedAsset(asset));
            return Err(CacheError::OracleDeviationCircuitBreaker {
                ws_price,
                oracle_price,
                max_bps: max_deviation_bps,
            });
        }

        let quote = DualVerifiedQuote {
            websocket_mid_usd: ws_price,
            onchain_oracle_usd: oracle_price,
            max_allowed_deviation_bps: max_deviation_bps,
        };

        self.store.put_with_ttl(
            CachedAsset(asset),
            quote,
            self.strict_ws_ttl,
            AdmissionPriority::ProtectedMain,
        )
    }

    /// Retrieves a fresh, MAC-verified, oracle-checked price for locking a 15-minute checkout quote.
    pub fn get_fresh_checkout_price(&self, asset: LogicalAsset) -> Result<UsdMicros, CacheError> {
        match self.store.get_verified(&CachedAsset(asset))? {
            Some(q) => Ok(q.websocket_mid_usd),
            None => Err(CacheError::StaleOrMissingQuote(asset)),
        }
    }
}
