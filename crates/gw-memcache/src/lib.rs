//! # gw-memcache
//!
//! Sovereign In-Memory Priority-Redundant Cache Engine (`gw-memcache`).
//!
//! # Architectural Classification
//! **Tier-0 Critical Infrastructure**
//! Replaces external Redis for the `O(1)` Watchlist Set, 10s Dual-Tier Price Quotes,
//! Idempotency Locks, and Zone C Enclave Replay Nonces.
//!
//! # Security Invariants (C1–C8)
//! - **C1:** Blake3 keyed shard routing and anti-HashDoS isolation.
//! - **C2:** Scan-resistant Segmented LRU admission policy (80% Protected / 20% Probationary).
//! - **C3:** Constant-time tag comparison via `subtle::ConstantTimeEq`.
//! - **C4:** ZeroizeOnDrop memory sanitization upon eviction or expiry.
//! - **C5:** Monotonic TTL expiration via `Instant` (immune to NTP rollback).
//! - **C6:** 128-byte cache-line aligned shards (`#[repr(align(128))]`) eliminating CPU false sharing.
//! - **C7:** Per-entry 32-byte Blake3 keyed MAC binding namespace, key, value, and timestamps.
//! - **C8:** Wait-free reads via copy-on-write reader snapshots for deposit address lookups.

#![forbid(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
#![warn(missing_docs)]

pub mod crypto_guard;
pub mod enclave_replay_guard;
pub mod price_oracle_cache;
pub mod sharded_engine;
pub mod traits;
pub mod watchlist_engine;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::enclave_replay_guard::EnclaveAntiReplayCache;
    use super::price_oracle_cache::PriceQuoteOracleCache;
    use super::traits::{CacheError, WatchlistMemoryEngine};
    use super::watchlist_engine::InProcessWatchlistEngine;
    use gw_primitives::{ChainId, LogicalAsset, UsdMicros};
    use std::time::Duration;

    const TEST_SEED: [u8; 64] = [0xA5_u8; 64];

    #[test]
    fn test_watchlist_o1_registration_and_zeroized_removal() {
        let engine = InProcessWatchlistEngine::new(&TEST_SEED, 10_000);
        let addr = "0x71c...89a".to_string();

        engine
            .register_watch_target(
                ChainId::EthereumMainnet,
                addr.clone(),
                1001,
                Duration::from_secs(900),
            )
            .unwrap_or_else(|e| panic!("Registration failed: {e}"));

        // Must match in O(1) time
        assert_eq!(
            engine.match_watched_target(ChainId::EthereumMainnet, &addr),
            Some(1001)
        );

        // Must not match on wrong chain
        assert_eq!(
            engine.match_watched_target(ChainId::BnbChain, &addr),
            None
        );

        // Unregister and zeroize
        engine.unregister_watch_target(ChainId::EthereumMainnet, &addr);
        assert_eq!(
            engine.match_watched_target(ChainId::EthereumMainnet, &addr),
            None
        );
    }

    #[test]
    fn test_oracle_deviation_circuit_breaker_blocks_poisoned_feed() {
        let price_cache = PriceQuoteOracleCache::new(&TEST_SEED);

        // Normal 0.2% deviation (20 bps <= 150 bps max) succeeds
        let ws_ok = UsdMicros(2_505_000_000); // $2,505.00
        let oracle_ok = UsdMicros(2_500_000_000); // $2,500.00
        assert!(price_cache
            .update_verified_quote(LogicalAsset::Eth, ws_ok, oracle_ok, 150)
            .is_ok());

        assert_eq!(
            price_cache.get_fresh_checkout_price(LogicalAsset::Eth),
            Ok(ws_ok)
        );

        // Flash-crash / spoofed WebSocket feed (5% deviation > 150 bps max) trips circuit breaker
        let ws_spoofed = UsdMicros(2_375_000_000); // $2,375.00
        let res = price_cache.update_verified_quote(LogicalAsset::Eth, ws_spoofed, oracle_ok, 150);
        assert!(matches!(
            res,
            Err(CacheError::OracleDeviationCircuitBreaker { .. })
        ));

        // Previous cached price was automatically purged & zeroized on circuit-breaker trip
        assert_eq!(
            price_cache.get_fresh_checkout_price(LogicalAsset::Eth),
            Err(CacheError::StaleOrMissingQuote(LogicalAsset::Eth))
        );
    }

    #[test]
    fn test_zone_c_enclave_anti_replay_guard_blocks_duplicate_tx_digest() {
        let guard = EnclaveAntiReplayCache::new(&TEST_SEED, 4096);
        let digest_hex =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();

        // First signing attempt succeeds
        assert!(guard
            .consume_envelope_digest_once(digest_hex.clone(), 1_776_000_000)
            .is_ok());

        // Second signing attempt with the same digest is immediately blocked
        assert!(matches!(
            guard.consume_envelope_digest_once(digest_hex, 1_776_000_005),
            Err(CacheError::ReplayAttackDetected(_))
        ));
    }
}
