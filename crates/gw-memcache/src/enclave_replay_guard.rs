//! # Zone C Enclave Anti-Replay Nonce Cache
//!
//! Provides atomic, zeroize-on-drop anti-replay protections inside Zone C Nitro Enclave RAM
//! to prevent duplicated transaction signing or M-of-N signature replay attacks.

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
use crate::traits::{CacheError, EnterpriseSecureCache};
use std::time::Duration;

/// Runs inside Zone C Enclave RAM to guarantee that no unsigned transaction digest
/// or M-of-N hardware approval signature can ever be executed twice.
pub struct EnclaveAntiReplayCache {
    consumed_digests: ShardedEnterpriseCache<String, u64>,
    retention_window: Duration,
}

impl EnclaveAntiReplayCache {
    /// Initializes the anti-replay cache with high-entropy seed and 7-day retention window.
    pub fn new(csprng_seed: &[u8; 64], max_nonces: usize) -> Self {
        Self {
            consumed_digests: ShardedEnterpriseCache::new(
                csprng_seed,
                b"ZONE_C_NONCE_V1!",
                max_nonces,
            ),
            retention_window: Duration::from_secs(86_400 * 7), // 7-day anti-replay memory lock
        }
    }

    /// Atomically marks a 32-byte transaction digest as consumed.
    /// Returns `Err(CacheError::ReplayAttackDetected)` if the digest was already signed.
    pub fn consume_envelope_digest_once(
        &self,
        envelope_sha256_hex: String,
        timestamp_unix: u64,
    ) -> Result<(), CacheError> {
        self.consumed_digests.put_if_absent_atomic(
            envelope_sha256_hex,
            timestamp_unix,
            self.retention_window,
        )
    }
}
