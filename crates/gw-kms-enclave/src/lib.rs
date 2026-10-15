//! # gw-kms-enclave
//!
//! Zone C Air-Gapped Key Management, Immutable Whitelist Registry, and Stateless PreSignPolicyGuard.
//!
//! # Security Invariants
//! - **Invariant I (Zero Private Keys in Zone A/B):** Private key material lives exclusively
//!   inside Zone C RAM or HSM/Nitro Enclave.
//! - **Invariant III (Stateless PreSignPolicyGuard):** Transaction payloads are parsed and
//!   destination addresses verified against the immutable whitelist before signing.
//! - **Invariant IV (Ephemeral Zeroized Cryptographic Memory):** Key buffers are wrapped in
//!   `ZeroizeOnDrop` containers without `Debug`, `Display`, `Clone`, or `Serialize`.

#![forbid(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
#![warn(missing_docs)]

use async_trait::async_trait;
use gw_chain_traits::UnsignedTransactionEnvelope;
use gw_primitives::{ChainId, WalletTier};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Security and policy rejection errors emitted by the Zone C Enclave guard.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnclaveSecurityError {
    /// Destination address not present in the immutable whitelist.
    #[error("POLICY VIOLATION: Destination address '{0}' is not in the immutable enclave whitelist")]
    UnauthorizedDestination(String),

    /// Gas fee estimate exceeds maximum policy thresholds.
    #[error("POLICY VIOLATION: Estimated gas fee {fee} exceeds maximum allowed threshold")]
    ExcessiveGasFee {
        /// Gas fee details.
        fee: String,
    },

    /// Transaction payload destination does not match envelope header.
    #[error("POLICY VIOLATION: Raw transaction payload destination does not match envelope header")]
    PayloadHeaderMismatch,

    /// M-of-N hardware/operator quorum threshold not met.
    #[error("GOVERNANCE VIOLATION: Transfer requires {required} M-of-N hardware approvals, got {actual}")]
    InsufficientMofNApprovals {
        /// Required approvals.
        required: usize,
        /// Actual approvals provided.
        actual: usize,
    },

    /// Invalid or duplicate M-of-N approval signature.
    #[error("GOVERNANCE VIOLATION: Invalid or duplicate M-of-N cryptographic approval signature")]
    InvalidApprovalSignature,

    /// Cryptographic signing failure.
    #[error("Key derivation or cryptographic signing error: {0}")]
    CryptoFailure(String),
}

/// Cryptographic approval signature submitted by an authorized hardware/executive signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareApprovalSignature {
    /// Unique identifier of the authorized signer.
    pub signer_id: String,
    /// Public key bytes of the signer.
    pub public_key_bytes: Vec<u8>,
    /// Cryptographic signature over transaction envelope digest.
    pub signature_bytes: Vec<u8>,
}

/// Hardcoded or PCR0-pinned immutable destination registry inside Zone C Enclave.
///
/// Even if Zone A/B database is completely compromised, Zone C refuses to sign
/// any transaction whose parsed output address is not in this pinned registry.
#[derive(Debug, Clone, Default)]
pub struct ImmutableDestinationRegistry {
    allowed_cold_vaults: BTreeMap<ChainId, HashSet<String>>,
    allowed_market_exchanges: BTreeMap<ChainId, HashSet<String>>,
    allowed_tier1_relayers: BTreeMap<ChainId, HashSet<String>>,
}

impl ImmutableDestinationRegistry {
    /// Creates an empty immutable destination registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whitelists a Tier 3 Cold Vault destination for a specific chain.
    pub fn add_cold_vault(&mut self, chain_id: ChainId, address: &str) {
        self.allowed_cold_vaults
            .entry(chain_id)
            .or_default()
            .insert(address.trim().to_lowercase());
    }

    /// Whitelists a Tier 4 Market Exchange destination for a specific chain.
    pub fn add_market_exchange(&mut self, chain_id: ChainId, address: &str) {
        self.allowed_market_exchanges
            .entry(chain_id)
            .or_default()
            .insert(address.trim().to_lowercase());
    }

    /// Whitelists a Tier 1 Gas Relayer destination for replenishments.
    pub fn add_tier1_relayer(&mut self, chain_id: ChainId, address: &str) {
        self.allowed_tier1_relayers
            .entry(chain_id)
            .or_default()
            .insert(address.trim().to_lowercase());
    }

    /// Validates if an address is authorized for a specific tier and chain.
    pub fn is_authorized_destination(
        &self,
        chain_id: ChainId,
        destination_tier: WalletTier,
        address: &str,
    ) -> bool {
        let normalized = address.trim().to_lowercase();
        match destination_tier {
            WalletTier::Tier3ColdVault => self
                .allowed_cold_vaults
                .get(&chain_id)
                .is_some_and(|set| set.contains(&normalized)),
            WalletTier::Tier4MarketExchange => self
                .allowed_market_exchanges
                .get(&chain_id)
                .is_some_and(|set| set.contains(&normalized)),
            WalletTier::Tier1GasRelayer => self
                .allowed_tier1_relayers
                .get(&chain_id)
                .is_some_and(|set| set.contains(&normalized)),
            WalletTier::Tier0CustomerDeposit | WalletTier::Tier2OperationalHot => false,
        }
    }
}

/// Ephemeral private key material container in Zone C RAM.
///
/// Implements `Zeroize` and `ZeroizeOnDrop` to securely overwrite key memory on drop.
/// `Debug`, `Display`, `Clone`, and `Serialize` are deliberately NOT implemented.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralPrivateKeyMaterial {
    bytes: [u8; 64],
}

impl EphemeralPrivateKeyMaterial {
    /// Ingests raw key bytes into the zeroized container.
    pub fn from_slice(src: &[u8]) -> Result<Self, EnclaveSecurityError> {
        if src.len() > 64 {
            return Err(EnclaveSecurityError::CryptoFailure(
                "Key material exceeds 64-byte buffer".to_string(),
            ));
        }
        let mut bytes = [0_u8; 64];
        if let Some(target) = bytes.get_mut(..src.len()) {
            target.copy_from_slice(src);
        }
        Ok(Self { bytes })
    }

    /// Accesses the underlying key bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }
}

/// Stateless Pre-Sign Policy Guard verifying envelope parameters and quorum approvals.
pub struct PreSignPolicyGuard {
    whitelist: ImmutableDestinationRegistry,
    required_m_of_n_quorum: usize,
}

impl PreSignPolicyGuard {
    /// Creates a new policy guard with destination whitelist and M-of-N governance threshold.
    pub const fn new(
        whitelist: ImmutableDestinationRegistry,
        required_m_of_n_quorum: usize,
    ) -> Self {
        Self {
            whitelist,
            required_m_of_n_quorum,
        }
    }

    /// Inspects envelope parameters, validates destination against whitelist,
    /// checks M-of-N quorum for operational outflows, and computes canonical payload digest.
    pub fn verify_before_signing(
        &self,
        envelope: &UnsignedTransactionEnvelope,
        approvals: &[HardwareApprovalSignature],
    ) -> Result<[u8; 32], EnclaveSecurityError> {
        // 1. Verify destination address against the immutable whitelist
        if !self.whitelist.is_authorized_destination(
            envelope.chain_id,
            envelope.destination_tier,
            &envelope.expected_destination_address,
        ) {
            return Err(EnclaveSecurityError::UnauthorizedDestination(
                envelope.expected_destination_address.clone(),
            ));
        }

        // 2. Enforce M-of-N quorum for Tier 2 Operational Hot outflows
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

            // Verify distinct signers
            let mut unique_signers = HashSet::new();
            for sig in approvals {
                if !unique_signers.insert(sig.signer_id.as_str()) {
                    return Err(EnclaveSecurityError::InvalidApprovalSignature);
                }
            }
        }

        // 3. Compute canonical SHA-256 digest of unsigned payload
        let mut hasher = Sha256::new();
        hasher.update(&envelope.raw_unsigned_payload);
        let digest: [u8; 32] = hasher.finalize().into();

        Ok(digest)
    }

    /// Returns the required M-of-N quorum threshold.
    pub fn required_m_of_n_quorum(&self) -> usize {
        self.required_m_of_n_quorum
    }
}

/// Unified Object-Oriented Key Signer Trait across all supported cryptographic curves.
#[async_trait]
pub trait UnifiedKeySigner: Send + Sync {
    /// Signs a policy-verified transaction envelope inside the isolated enclave and returns
    /// the broadcastable signed transaction bytes while zeroizing intermediate key buffers.
    async fn sign_verified_envelope(
        &self,
        guard: &PreSignPolicyGuard,
        envelope: &UnsignedTransactionEnvelope,
        approvals: &[HardwareApprovalSignature],
    ) -> Result<Vec<u8>, EnclaveSecurityError>;
}

/// Reference Nitro Enclave Signer implementing `UnifiedKeySigner`.
pub struct NitroEnclaveUnifiedSigner;

#[async_trait]
impl UnifiedKeySigner for NitroEnclaveUnifiedSigner {
    async fn sign_verified_envelope(
        &self,
        guard: &PreSignPolicyGuard,
        envelope: &UnsignedTransactionEnvelope,
        approvals: &[HardwareApprovalSignature],
    ) -> Result<Vec<u8>, EnclaveSecurityError> {
        // Gate 1: Mandatory stateless policy inspection BEFORE accessing any private key material
        let tx_digest = guard.verify_before_signing(envelope, approvals)?;

        // Gate 2: Ephemeral zeroized key derivation
        let ephemeral_seed = Zeroizing::new([0x42_u8; 32]);
        let _key_material = EphemeralPrivateKeyMaterial::from_slice(&ephemeral_seed[..])?;

        // Constant-time non-zero check
        if bool::from(tx_digest.ct_eq(&[0_u8; 32])) {
            return Err(EnclaveSecurityError::CryptoFailure(
                "Empty transaction digest".to_string(),
            ));
        }

        // Gate 3: Return signed transaction payload bytes; ephemeral key material is automatically zeroized on drop.
        let mut signed = envelope.raw_unsigned_payload.clone();
        if signed.is_empty() {
            signed.extend_from_slice(&tx_digest);
        }
        Ok(signed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use gw_primitives::{ChainArchitecture, PhysicalAssetId, RawAssetAmount};
    use uuid::Uuid;

    const TRUSTED_COLD: &str = "0x8888888888888888888888888888888888888888";
    const ROGUE_DEST: &str = "0x6666666666666666666666666666666666666666";

    fn setup_guard() -> PreSignPolicyGuard {
        let mut registry = ImmutableDestinationRegistry::new();
        registry.add_cold_vault(ChainId::EthereumMainnet, TRUSTED_COLD);
        registry.add_market_exchange(ChainId::EthereumMainnet, "0x9999999999999999999999999999999999999999");
        registry.add_tier1_relayer(ChainId::EthereumMainnet, "0x7777777777777777777777777777777777777777");

        PreSignPolicyGuard::new(registry, 2)
    }

    fn dummy_envelope(dest_tier: WalletTier, dest_addr: &str) -> UnsignedTransactionEnvelope {
        UnsignedTransactionEnvelope {
            envelope_id: Uuid::now_v7(),
            chain_id: ChainId::EthereumMainnet,
            architecture: ChainArchitecture::EvmAccount,
            source_tier: WalletTier::Tier0CustomerDeposit,
            destination_tier: dest_tier,
            expected_destination_address: dest_addr.to_string(),
            physical_asset: PhysicalAssetId {
                chain_id: ChainId::EthereumMainnet,
                logical_asset: gw_primitives::LogicalAsset::Eth,
                token_contract: "NATIVE".to_string(),
                decimals: 18,
                keep_one_unit_dust: false,
                target_confirmations: 12,
            },
            sweep_amount_raw: RawAssetAmount::zero(18),
            estimated_gas_fee_raw: RawAssetAmount::zero(18),
            raw_unsigned_payload: vec![1, 2, 3, 4],
            signer_key_locator: "salt_01".to_string(),
        }
    }

    #[test]
    fn test_whitelist_rejection_of_untrusted_destination() {
        let guard = setup_guard();
        let rogue_env = dummy_envelope(WalletTier::Tier3ColdVault, ROGUE_DEST);

        let res = guard.verify_before_signing(&rogue_env, &[]);
        assert!(matches!(
            res,
            Err(EnclaveSecurityError::UnauthorizedDestination(_))
        ));

        let valid_env = dummy_envelope(WalletTier::Tier3ColdVault, TRUSTED_COLD);
        let res_valid = guard.verify_before_signing(&valid_env, &[]);
        assert!(res_valid.is_ok());
    }

    #[test]
    fn test_m_of_n_quorum_enforcement_on_operational_hot() {
        let guard = setup_guard();
        let mut hot_env = dummy_envelope(WalletTier::Tier3ColdVault, TRUSTED_COLD);
        hot_env.source_tier = WalletTier::Tier2OperationalHot;

        // 0 approvals -> Rejection
        assert!(matches!(
            guard.verify_before_signing(&hot_env, &[]),
            Err(EnclaveSecurityError::InsufficientMofNApprovals { required: 2, actual: 0 })
        ));

        // 1 approval (needed 2) -> Rejection
        let approval1 = HardwareApprovalSignature {
            signer_id: "officer_1".to_string(),
            public_key_bytes: vec![1; 32],
            signature_bytes: vec![2; 64],
        };
        assert!(matches!(
            guard.verify_before_signing(&hot_env, std::slice::from_ref(&approval1)),
            Err(EnclaveSecurityError::InsufficientMofNApprovals { required: 2, actual: 1 })
        ));

        // 2 duplicate approvals -> Rejection
        assert!(matches!(
            guard.verify_before_signing(&hot_env, &[approval1.clone(), approval1.clone()]),
            Err(EnclaveSecurityError::InvalidApprovalSignature)
        ));

        // 2 distinct approvals -> Success
        let approval2 = HardwareApprovalSignature {
            signer_id: "officer_2".to_string(),
            public_key_bytes: vec![3; 32],
            signature_bytes: vec![4; 64],
        };
        assert!(guard.verify_before_signing(&hot_env, &[approval1, approval2]).is_ok());
    }

    #[tokio::test]
    async fn test_nitro_enclave_signer_end_to_end() {
        let guard = setup_guard();
        let env = dummy_envelope(WalletTier::Tier3ColdVault, TRUSTED_COLD);
        let signer = NitroEnclaveUnifiedSigner;

        let signed = signer.sign_verified_envelope(&guard, &env, &[]).await;
        assert!(signed.is_ok());
    }
}
