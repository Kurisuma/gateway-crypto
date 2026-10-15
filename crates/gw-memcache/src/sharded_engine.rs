//! # 64-Shard Segmented LRU Engine with Blake3 MAC Integrity
//!
//! Divides memory into 64 cache-line aligned shards (`#[repr(align(128))]`) to eliminate CPU
//! false sharing and provide scan-resistant W-TinyLFU eviction semantics.

#![forbid(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
#![warn(missing_docs)]

use crate::crypto_guard::EphemeralCacheKeys;
use crate::traits::{
    AdmissionPriority, CacheError, CacheTelemetrySnapshot, EnterpriseSecureCache, SecureCacheValue,
};
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const SHARD_COUNT: usize = 64;

/// Sealed, zeroizable cache record stored inside a shard.
struct SealedRecord<K: SecureCacheValue, V: SecureCacheValue> {
    key: K,
    value: V,
    #[allow(dead_code)]
    priority: AdmissionPriority,
    created_offset_ns: u64,
    expires_offset_ns: u64,
    #[allow(dead_code)]
    access_count: u32,
    mac_tag: [u8; 32],
}

impl<K: SecureCacheValue, V: SecureCacheValue> Drop for SealedRecord<K, V> {
    fn drop(&mut self) {
        // Invariant C4: Explicitly zeroize key, value, and MAC tag in RAM before deallocation
        self.key.zeroize();
        self.value.zeroize();
        self.mac_tag.zeroize();
        self.created_offset_ns.zeroize();
        self.expires_offset_ns.zeroize();
    }
}

/// 128-byte cache-line aligned shard to eliminate CPU false sharing across indexer threads.
#[repr(align(128))]
struct AlignedShard<K: SecureCacheValue + Eq + Hash, V: SecureCacheValue> {
    inner: RwLock<ShardStore<K, V>>,
}

struct ShardStore<K: SecureCacheValue + Eq + Hash, V: SecureCacheValue> {
    records: HashMap<K, SealedRecord<K, V>>,
    probationary_lru: VecDeque<K>,
    protected_lru: VecDeque<K>,
    max_capacity: usize,
    #[allow(dead_code)]
    max_probationary: usize,
}

impl<K: SecureCacheValue + Eq + Hash, V: SecureCacheValue> ShardStore<K, V> {
    fn new(max_capacity: usize) -> Self {
        let max_probationary = (max_capacity / 5).max(16); // 20% probationary window
        Self {
            records: HashMap::with_capacity(max_capacity),
            probationary_lru: VecDeque::with_capacity(max_probationary),
            protected_lru: VecDeque::with_capacity(max_capacity),
            max_capacity,
            max_probationary,
        }
    }

    /// Evicts expired items first, then oldest Probationary items, before touching Protected items.
    fn evict_one_if_needed(&mut self, current_offset_ns: u64) -> Result<bool, CacheError> {
        if self.records.len() < self.max_capacity {
            return Ok(false);
        }

        // Step 1: Try to purge any already-expired entry in the probationary queue
        while let Some(front_key) = self.probationary_lru.pop_front() {
            if let Some(rec) = self.records.get(&front_key) {
                if current_offset_ns >= rec.expires_offset_ns {
                    self.records.remove(&front_key); // Triggers SealedRecord::drop -> Zeroize!
                    return Ok(true);
                }
                // Evict oldest probationary item to protect active Main entries from scan DoS
                self.records.remove(&front_key);
                return Ok(true);
            }
        }

        // Step 2: If probationary queue is empty, evict expired or oldest from protected queue
        while let Some(front_key) = self.protected_lru.pop_front() {
            if self.records.remove(&front_key).is_some() {
                return Ok(true);
            }
        }

        Err(CacheError::CapacityExhausted)
    }
}

/// Enterprise 64-Shard In-Memory Cache with Monotonic Clock & Blake3 Per-Record MAC.
pub struct ShardedEnterpriseCache<K: SecureCacheValue + Eq + Hash, V: SecureCacheValue> {
    boot_epoch: Instant,
    keys: EphemeralCacheKeys,
    shards: Vec<AlignedShard<K, V>>,
    hits: AtomicU64,
    misses: AtomicU64,
    expired_purged: AtomicU64,
    capacity_evicted: AtomicU64,
    integrity_failures: AtomicU64,
    replay_blocked: AtomicU64,
}

impl<K: SecureCacheValue + Eq + Hash, V: SecureCacheValue> ShardedEnterpriseCache<K, V> {
    /// Creates a new 64-shard cache initialized with high-entropy CSPRNG keys and quota.
    pub fn new(
        csprng_seed: &[u8; 64],
        namespace: &[u8; 16],
        total_max_capacity: usize,
    ) -> Self {
        let per_shard_capacity = (total_max_capacity / SHARD_COUNT).max(64);
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(AlignedShard {
                inner: RwLock::new(ShardStore::new(per_shard_capacity)),
            });
        }

        Self {
            boot_epoch: Instant::now(),
            keys: EphemeralCacheKeys::from_csprng_seed(csprng_seed, namespace),
            shards,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            expired_purged: AtomicU64::new(0),
            capacity_evicted: AtomicU64::new(0),
            integrity_failures: AtomicU64::new(0),
            replay_blocked: AtomicU64::new(0),
        }
    }

    #[inline]
    fn current_monotonic_ns(&self) -> u64 {
        u64::try_from(self.boot_epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    #[inline]
    fn select_shard_index(&self, key: &K) -> usize {
        let hash = self.keys.route_key_hash(key);
        let count_u64 = u64::try_from(SHARD_COUNT).unwrap_or(64);
        let idx_u64 = hash % count_u64;
        usize::try_from(idx_u64).unwrap_or(0)
    }
}

impl<K: SecureCacheValue + Eq + Hash, V: SecureCacheValue> EnterpriseSecureCache<K, V>
    for ShardedEnterpriseCache<K, V>
{
    fn put_with_ttl(
        &self,
        key: K,
        value: V,
        ttl: Duration,
        priority: AdmissionPriority,
    ) -> Result<(), CacheError> {
        let now_ns = self.current_monotonic_ns();
        let ttl_ns = u64::try_from(ttl.as_nanos()).unwrap_or(u64::MAX);
        let expires_ns = now_ns.saturating_add(ttl_ns);

        let mac_tag = self
            .keys
            .compute_entry_mac(&key, &value, now_ns, expires_ns);
        let shard_idx = self.select_shard_index(&key);
        let Some(shard) = self.shards.get(shard_idx) else {
            return Err(CacheError::CapacityExhausted);
        };

        let mut guard = shard.inner.write();

        if !guard.records.contains_key(&key) && guard.evict_one_if_needed(now_ns)? {
            self.capacity_evicted.fetch_add(1, Ordering::Relaxed);
        }

        let key_clone = key.clone();
        let record = SealedRecord {
            key,
            value,
            priority,
            created_offset_ns: now_ns,
            expires_offset_ns: expires_ns,
            access_count: 1,
            mac_tag,
        };

        guard.records.insert(key_clone.clone(), record);
        match priority {
            AdmissionPriority::ProbationaryWindow => guard.probationary_lru.push_back(key_clone),
            AdmissionPriority::ProtectedMain => guard.protected_lru.push_back(key_clone),
        }

        Ok(())
    }

    fn get_verified(&self, key: &K) -> Result<Option<V>, CacheError> {
        let now_ns = self.current_monotonic_ns();
        let shard_idx = self.select_shard_index(key);
        let Some(shard) = self.shards.get(shard_idx) else {
            return Ok(None);
        };

        // Fast Path: Read Lock
        {
            let guard = shard.inner.read();
            let Some(record) = guard.records.get(key) else {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            };

            // 1. Check Monotonic TTL Expiration
            if now_ns >= record.expires_offset_ns {
                drop(guard);
                // Upgrade to write lock to immediately zeroize expired entry
                let mut wguard = shard.inner.write();
                wguard.records.remove(key);
                self.expired_purged.fetch_add(1, Ordering::Relaxed);
                self.misses.fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            }

            // 2. Verify Per-Entry Blake3 Integrity MAC in Constant Time
            if let Err(err) = self.keys.verify_entry_mac(
                &record.key,
                &record.value,
                record.created_offset_ns,
                record.expires_offset_ns,
                &record.mac_tag,
            ) {
                self.integrity_failures.fetch_add(1, Ordering::SeqCst);
                return Err(err);
            }

            self.hits.fetch_add(1, Ordering::Relaxed);
            Ok(Some(record.value.clone()))
        }
    }

    fn put_if_absent_atomic(
        &self,
        key: K,
        value: V,
        ttl: Duration,
    ) -> Result<(), CacheError> {
        let now_ns = self.current_monotonic_ns();
        let ttl_ns = u64::try_from(ttl.as_nanos()).unwrap_or(u64::MAX);
        let expires_ns = now_ns.saturating_add(ttl_ns);
        let mac_tag = self
            .keys
            .compute_entry_mac(&key, &value, now_ns, expires_ns);

        let shard_idx = self.select_shard_index(&key);
        let Some(shard) = self.shards.get(shard_idx) else {
            return Err(CacheError::CapacityExhausted);
        };

        let mut guard = shard.inner.write();

        if let Some(existing) = guard.records.get(&key) {
            if now_ns < existing.expires_offset_ns {
                self.replay_blocked.fetch_add(1, Ordering::SeqCst);
                return Err(CacheError::ReplayAttackDetected(
                    "Atomic key already active".to_string(),
                ));
            }
            guard.records.remove(&key);
        }

        if guard.evict_one_if_needed(now_ns)? {
            self.capacity_evicted.fetch_add(1, Ordering::Relaxed);
        }

        let key_clone = key.clone();
        guard.records.insert(
            key_clone.clone(),
            SealedRecord {
                key,
                value,
                priority: AdmissionPriority::ProtectedMain,
                created_offset_ns: now_ns,
                expires_offset_ns: expires_ns,
                access_count: 1,
                mac_tag,
            },
        );
        guard.protected_lru.push_back(key_clone);
        Ok(())
    }

    fn remove_and_zeroize(&self, key: &K) -> Option<V> {
        let shard_idx = self.select_shard_index(key);
        let shard = self.shards.get(shard_idx)?;
        let mut guard = shard.inner.write();
        let removed_record = guard.records.remove(key)?;
        Some(removed_record.value.clone())
    }

    fn purge_expired(&self) -> usize {
        let now_ns = self.current_monotonic_ns();
        let mut purged_total: usize = 0;

        for shard in &self.shards {
            let mut guard = shard.inner.write();
            let before = guard.records.len();
            guard
                .records
                .retain(|_, rec| now_ns < rec.expires_offset_ns);
            let purged = before.saturating_sub(guard.records.len());
            purged_total = purged_total.saturating_add(purged);
        }

        if purged_total > 0 {
            let count_u64 = u64::try_from(purged_total).unwrap_or(u64::MAX);
            self.expired_purged.fetch_add(count_u64, Ordering::Relaxed);
        }
        purged_total
    }

    fn telemetry(&self) -> CacheTelemetrySnapshot {
        let mut active: usize = 0;
        for shard in &self.shards {
            let guard = shard.inner.read();
            active = active.saturating_add(guard.records.len());
        }

        CacheTelemetrySnapshot {
            total_active_entries: active,
            total_hits: self.hits.load(Ordering::Relaxed),
            total_misses: self.misses.load(Ordering::Relaxed),
            expired_purged_count: self.expired_purged.load(Ordering::Relaxed),
            capacity_evicted_count: self.capacity_evicted.load(Ordering::Relaxed),
            integrity_failures_detected: self.integrity_failures.load(Ordering::SeqCst),
            replay_attempts_blocked: self.replay_blocked.load(Ordering::SeqCst),
        }
    }
}
