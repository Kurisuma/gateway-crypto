//! # Cryptographic Ephemeral Keys & Integrity Guard
//!
//! Manages per-boot ephemeral keys, anti-HashDoS routing hashes, and 32-byte Blake3 keyed MACs.

#![forbid(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
#![warn(missing_docs)]

use crate::traits::{CacheError, SecureCacheValue};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Holds the per-boot ephemeral 256-bit keys in zeroized memory.
/// Never implements Debug, Display, Clone, or Serialize to prevent accidental leaks.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralCacheKeys {
    shard_routing_key: [u8; 32],
    mac_integrity_key: [u8; 32],
    namespace_id: [u8; 16],
}

impl EphemeralCacheKeys {
    /// Initializes keys from a high-entropy 64-byte CSPRNG seed provided at startup.
    pub fn from_csprng_seed(seed_64_bytes: &[u8; 64], namespace: &[u8; 16]) -> Self {
        let mut shard_routing_key = [0_u8; 32];
        let mut mac_integrity_key = [0_u8; 32];
        shard_routing_key.copy_from_slice(
            seed_64_bytes
                .get(0..32)
                .unwrap_or(&[0_u8; 32]),
        );
        mac_integrity_key.copy_from_slice(
            seed_64_bytes
                .get(32..64)
                .unwrap_or(&[0_u8; 32]),
        );

        Self {
            shard_routing_key,
            mac_integrity_key,
            namespace_id: *namespace,
        }
    }

    /// Computes a collision-resistant 64-bit hash for shard selection using keyed Blake3.
    pub fn route_key_hash<K: SecureCacheValue>(&self, key: &K) -> u64 {
        let mut hasher = blake3::Hasher::new_keyed(&self.shard_routing_key);
        hasher.update(&self.namespace_id);
        key.update_mac_hasher(&mut hasher);
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(
            digest
                .as_bytes()
                .get(0..8)
                .unwrap_or(&[0_u8; 8]),
        );
        u64::from_le_bytes(bytes)
    }

    /// Computes a 32-byte keyed MAC binding `(namespace || created_ns || expires_ns || key || value)`.
    pub fn compute_entry_mac<K: SecureCacheValue, V: SecureCacheValue>(
        &self,
        key: &K,
        value: &V,
        created_offset_ns: u64,
        expires_offset_ns: u64,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.mac_integrity_key);
        hasher.update(&self.namespace_id);
        hasher.update(&created_offset_ns.to_le_bytes());
        hasher.update(&expires_offset_ns.to_le_bytes());
        key.update_mac_hasher(&mut hasher);
        value.update_mac_hasher(&mut hasher);
        *hasher.finalize().as_bytes()
    }

    /// Verifies the entry's 32-byte integrity tag in constant time (`subtle::ConstantTimeEq`).
    pub fn verify_entry_mac<K: SecureCacheValue, V: SecureCacheValue>(
        &self,
        key: &K,
        value: &V,
        created_offset_ns: u64,
        expires_offset_ns: u64,
        expected_tag: &[u8; 32],
    ) -> Result<(), CacheError> {
        let actual_tag =
            self.compute_entry_mac(key, value, created_offset_ns, expires_offset_ns);
        if bool::from(actual_tag.ct_eq(expected_tag)) {
            Ok(())
        } else {
            Err(CacheError::IntegrityCheckFailed)
        }
    }
}

// Implement `SecureCacheValue` for standard primitive types used in the workspace

impl SecureCacheValue for String {
    fn update_mac_hasher(&self, hasher: &mut blake3::Hasher) {
        let len_u64 = u64::try_from(self.len()).unwrap_or(u64::MAX);
        hasher.update(&len_u64.to_le_bytes());
        hasher.update(self.as_bytes());
    }
}

impl SecureCacheValue for u64 {
    fn update_mac_hasher(&self, hasher: &mut blake3::Hasher) {
        hasher.update(&self.to_le_bytes());
    }
}
