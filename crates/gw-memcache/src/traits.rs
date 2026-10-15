//! # Cache Traits & Contracts
//!
//! Object-oriented trait definitions for the Sovereign In-Memory Priority-Redundant
//! Cache Engine (`gw-memcache`), including strict zeroize bounds, monotonic TTL semantics,
//! and admission priority policies.

#![forbid(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
#![warn(missing_docs)]

use gw_primitives::{ChainId, LogicalAsset, UsdMicros};
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroize;

/// Error taxonomy for in-memory cache operations, integrity violations, and circuit breakers.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CacheError {
    /// Memory corruption or tampering detected: Blake3 MAC tag verification failed in constant time.
    #[error("CRITICAL SECURITY ALERT: Memory integrity MAC verification failed for key")]
    IntegrityCheckFailed,

    /// Shard capacity exhausted and all admission queues refused eviction.
    #[error("Cache shard capacity exhausted and protected policy refused eviction")]
    CapacityExhausted,

    /// Monotonic TTL expired before this retrieval attempt.
    #[error("Entry expired at monotonic tick")]
    EntryExpired,

    /// Anti-replay nonce or idempotency key already consumed in Zone C or API gateway.
    #[error("Replay attack detected: Nonce or Idempotency key '{0}' already consumed")]
    ReplayAttackDetected(String),

    /// Price deviation between WebSocket stream and on-chain oracle exceeded maximum allowed basis points.
    #[error(
        "Oracle price deviation circuit breaker triggered: ws={ws_price}, oracle={oracle_price} (> {max_bps} bps)"
    )]
    OracleDeviationCircuitBreaker {
        /// Real-time WebSocket mid-price in USD micros.
        ws_price: UsdMicros,
        /// On-chain oracle verified price in USD micros.
        oracle_price: UsdMicros,
        /// Max allowed divergence threshold in basis points.
        max_bps: u16,
    },

    /// No valid, non-expired price quote available in memory for the given logical asset.
    #[error("Price quote expired or missing for asset {0:?}")]
    StaleOrMissingQuote(LogicalAsset),
}

/// Marker trait required for all keys and values stored in `gw-memcache`.
///
/// Enforces that every cached item can be deterministically fed into the Blake3
/// keyed MAC hasher and cryptographically zeroed in RAM upon eviction or expiration.
pub trait SecureCacheValue: Clone + Send + Sync + Zeroize + 'static {
    /// Writes the canonical byte representation of this instance into the MAC hasher.
    fn update_mac_hasher(&self, hasher: &mut blake3::Hasher);
}

/// Eviction priority tier for scan-resistant Segmented LRU (`W-TinyLFU` style).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionPriority {
    /// Guest checkouts and unverified single-request entries (evicted first under memory pressure).
    ProbationaryWindow,
    /// Authenticated customer checkouts, active `DETECTED` invoices, and oracle prices (protected).
    ProtectedMain,
}

/// Real-time security and performance telemetry snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheTelemetrySnapshot {
    /// Total entries currently resident across all 64 shards.
    pub total_active_entries: usize,
    /// Total verified cache hits.
    pub total_hits: u64,
    /// Total cache misses (non-existent or expired).
    pub total_misses: u64,
    /// Total expired entries purged during background or read sweeps.
    pub expired_purged_count: u64,
    /// Total entries evicted to enforce capacity limits under memory pressure.
    pub capacity_evicted_count: u64,
    /// Total MAC integrity verification failures detected.
    pub integrity_failures_detected: u64,
    /// Total atomic replay or idempotency duplication attempts blocked.
    pub replay_attempts_blocked: u64,
}

/// Core Object-Oriented Trait for the Enterprise In-Memory Key-Value Store.
pub trait EnterpriseSecureCache<K, V>: Send + Sync
where
    K: SecureCacheValue + Eq + std::hash::Hash,
    V: SecureCacheValue,
{
    /// Inserts or updates a value with a strict monotonic TTL, admission priority, and Blake3 MAC tag.
    fn put_with_ttl(
        &self,
        key: K,
        value: V,
        ttl: Duration,
        priority: AdmissionPriority,
    ) -> Result<(), CacheError>;

    /// Retrieves a clone of the value if and only if:
    /// 1. The entry exists,
    /// 2. `Instant::now() < entry.expires_at` (Monotonic clock check), AND
    /// 3. The 32-byte keyed Blake3 integrity tag matches in constant time.
    fn get_verified(&self, key: &K) -> Result<Option<V>, CacheError>;

    /// Atomically inserts a key only if it does not currently exist (or is expired).
    /// Used for atomic idempotency locks and anti-replay nonces.
    fn put_if_absent_atomic(
        &self,
        key: K,
        value: V,
        ttl: Duration,
    ) -> Result<(), CacheError>;

    /// Explicitly removes an entry and immediately overwrites its memory with zeroes.
    fn remove_and_zeroize(&self, key: &K) -> Option<V>;

    /// Sweeps all shards, zeroizing and deallocating all expired entries.
    fn purge_expired(&self) -> usize;

    /// Returns live operational and security metrics.
    fn telemetry(&self) -> CacheTelemetrySnapshot;
}

/// Specialized O(1) Watchlist Trait for Native Block Indexers.
pub trait WatchlistMemoryEngine: Send + Sync {
    /// Registers an active deposit address, Solana reference pubkey, or TON memo tag.
    fn register_watch_target(
        &self,
        chain_id: ChainId,
        lookup_key: String,
        invoice_id: u64,
        ttl: Duration,
    ) -> Result<(), CacheError>;

    /// Wait-free O(1) lookup called by native block indexers on every transaction output.
    fn match_watched_target(&self, chain_id: ChainId, lookup_key: &str) -> Option<u64>;

    /// Removes a completed or expired watch target and zeroizes its routing metadata.
    fn unregister_watch_target(&self, chain_id: ChainId, lookup_key: &str);
}
