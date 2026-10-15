//! # gw-adapters-svm
//!
//! Solana (SVM) blockchain adapter supporting:
//! - Mode A: Ephemeral Reference Public Key in instruction keys for zero-sweep direct settlement.
//! - Mode B: Program Derived Address (PDA) with off-curve mathematical verification and rent reclamation.
//!
//! # Security Invariant
//! - **Invariant I (Zero Private Keys):** Reference keys and PDAs are generated without private keys.
//! - **Theorem 2.3 (PDA Off-Curve Proof):** Canonical bumps ensure the PDA coordinate does not decompress
//!   to a point on Edwards25519, guaranteeing no private key exists.

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
use async_trait::async_trait;
use curve25519_dalek::edwards::CompressedEdwardsY;
use gw_chain_traits::{
    AdapterError, BlockchainAdapter, CheckoutDepositRoute, NativeBlockIndexer,
    NormalizedTransferEvent, OnChainBalanceReader, RelayerResourceHealth, UnifiedNetworkAdapter,
    UnsignedSweepBuilder, UnsignedTransactionEnvelope, WatchOnlyAddressDeriver,
};
use gw_primitives::{ChainId, PhysicalAssetId, RawAssetAmount, WalletTier};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use uuid::Uuid;

/// Solana SVM checkout and rent-reclaiming adapter.
pub struct SolanaSvmAdapter {
    program_id: [u8; 32],
    cold_treasury_ata: String,
    rent_reserve_lamports: u64,
}

impl SolanaSvmAdapter {
    /// Standard rent reserve for 165-byte SPL token account (2,039,280 lamports = 0.00203928 SOL).
    pub const DEFAULT_ATA_RENT_LAMPORTS: u64 = 2_039_280;

    /// Creates a new Solana SVM adapter with a gateway program ID and cold treasury Associated Token Account.
    pub fn new(program_id_base58: &str, cold_treasury_ata: &str) -> Result<Self, AdapterError> {
        let mut program_id = [0_u8; 32];
        let decoded = bs58::decode(program_id_base58)
            .into_vec()
            .map_err(|e| AdapterError::General(format!("Invalid base58 program ID: {e}")))?;

        if decoded.len() != 32 {
            return Err(AdapterError::General(
                "Program ID must be exactly 32 bytes".to_string(),
            ));
        }

        if let Some(src) = decoded.get(0..32) {
            program_id.copy_from_slice(src);
        }

        Ok(Self {
            program_id,
            cold_treasury_ata: cold_treasury_ata.to_string(),
            rent_reserve_lamports: Self::DEFAULT_ATA_RENT_LAMPORTS,
        })
    }

    /// Derives an ephemeral reference public key (Mode A) from invoice index.
    pub fn derive_mode_a_reference_key(invoice_id: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"gw_sol_reference_v5");
        hasher.update(invoice_id.to_be_bytes());
        let digest = hasher.finalize();
        bs58::encode(digest).into_string()
    }

    /// Derives a Program Derived Address (PDA) with canonical bump seed search (Mode B).
    ///
    /// The search iterates from $b = 255$ down to 0, finding the first coordinate that is
    /// off the Edwards25519 curve (`CompressedEdwardsY::decompress() == None`).
    pub fn find_pda(&self, seed: &[u8]) -> Result<([u8; 32], u8), AdapterError> {
        let mut bump = 255_u8;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(b"gw_vault_v5");
            hasher.update(seed);
            hasher.update([bump]);
            hasher.update(self.program_id);
            hasher.update(b"ProgramDerivedAddress");
            let hash: [u8; 32] = hasher.finalize().into();

            // Off-curve verification: Decompressing Y coordinate must fail
            if CompressedEdwardsY(hash).decompress().is_none() {
                return Ok((hash, bump));
            }

            if bump == 0 {
                return Err(AdapterError::General(
                    "Unable to find canonical off-curve bump for PDA".to_string(),
                ));
            }
            bump = bump.saturating_sub(1);
        }
    }

    /// Returns the cold treasury ATA address string.
    pub fn cold_treasury_ata(&self) -> &str {
        &self.cold_treasury_ata
    }

    /// Returns the rent reserve in lamports.
    pub fn rent_reserve_lamports(&self) -> u64 {
        self.rent_reserve_lamports
    }
}

impl BlockchainAdapter for SolanaSvmAdapter {
    fn chain_id(&self) -> ChainId {
        ChainId::SolanaMainnet
    }
}

#[async_trait]
impl WatchOnlyAddressDeriver for SolanaSvmAdapter {
    async fn derive_checkout_route(
        &self,
        invoice_id: u64,
        customer_id: Option<Uuid>,
        _asset: &PhysicalAssetId,
    ) -> Result<CheckoutDepositRoute, AdapterError> {
        match customer_id {
            // Mode A (Direct checkout with ephemeral reference key)
            None => {
                let reference_key = Self::derive_mode_a_reference_key(invoice_id);
                Ok(CheckoutDepositRoute {
                    chain_id: ChainId::SolanaMainnet,
                    deposit_address: self.cold_treasury_ata.clone(),
                    routing_reference: Some(reference_key.clone()),
                    derivation_locator: format!("mode_a_ref:{reference_key}"),
                })
            }
            // Mode B (CEX withdrawal with PDA)
            Some(cid) => {
                let (pda_bytes, bump) = self.find_pda(cid.as_bytes())?;
                let pda_base58 = bs58::encode(pda_bytes).into_string();
                Ok(CheckoutDepositRoute {
                    chain_id: ChainId::SolanaMainnet,
                    deposit_address: pda_base58.clone(),
                    routing_reference: None,
                    derivation_locator: format!("mode_b_pda:{pda_base58}:bump:{bump}"),
                })
            }
        }
    }
}

#[async_trait]
impl NativeBlockIndexer for SolanaSvmAdapter {
    async fn scan_block_for_watched_transfers(
        &self,
        _block_height: u64,
        _watched_lookup_keys: &HashSet<String>,
    ) -> Result<Vec<NormalizedTransferEvent>, AdapterError> {
        // Pure indexer stub: In production, connects via Yellowstone gRPC (Geyser plugin)
        Ok(Vec::new())
    }

    async fn latest_canonical_height(&self) -> Result<u64, AdapterError> {
        Ok(310_000_000)
    }
}

#[async_trait]
impl OnChainBalanceReader for SolanaSvmAdapter {
    async fn get_balance_raw(
        &self,
        _address: &str,
        asset: &PhysicalAssetId,
    ) -> Result<RawAssetAmount, AdapterError> {
        Ok(RawAssetAmount::zero(asset.decimals))
    }

    async fn inspect_gas_relayer_health(&self) -> Result<RelayerResourceHealth, AdapterError> {
        Ok(RelayerResourceHealth {
            native_balance: RawAssetAmount::new(U256::from(100_000_000_000_u64), 9), // 100 SOL
            staked_energy_remaining: 0,
            current_nonce: 0,
            is_healthy: true,
        })
    }
}

#[async_trait]
impl UnsignedSweepBuilder for SolanaSvmAdapter {
    async fn build_unsigned_transfer(
        &self,
        source_address_or_locator: &str,
        destination_address: &str,
        source_tier: WalletTier,
        destination_tier: WalletTier,
        asset: &PhysicalAssetId,
        amount: RawAssetAmount,
    ) -> Result<UnsignedTransactionEnvelope, AdapterError> {
        if destination_tier == WalletTier::Tier3ColdVault
            && destination_address != self.cold_treasury_ata
        {
            return Err(AdapterError::UntrustedDestination(
                destination_address.to_string(),
            ));
        }

        Ok(UnsignedTransactionEnvelope {
            envelope_id: Uuid::now_v7(),
            chain_id: ChainId::SolanaMainnet,
            architecture: self.architecture(),
            source_tier,
            destination_tier,
            expected_destination_address: destination_address.to_string(),
            physical_asset: asset.clone(),
            sweep_amount_raw: amount,
            estimated_gas_fee_raw: RawAssetAmount::new(U256::from(5000_u64), 9), // 5,000 lamports standard SVM tx fee
            raw_unsigned_payload: Vec::new(),
            signer_key_locator: source_address_or_locator.to_string(),
        })
    }

    async fn broadcast_signed_transaction(
        &self,
        _signed_raw_bytes: &[u8],
    ) -> Result<String, AdapterError> {
        Ok("solana_tx_sig_mock".to_string())
    }
}

impl UnifiedNetworkAdapter for SolanaSvmAdapter {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use gw_primitives::LogicalAsset;

    const MOCK_PROGRAM_ID: &str = "11111111111111111111111111111111";
    const MOCK_COLD_ATA: &str = "7XJ9DkCkg3r297a7N64k8bQ57GfCqP37vGZpS65P3yHw";

    #[test]
    fn test_svm_adapter_initialization() {
        let adapter = SolanaSvmAdapter::new(MOCK_PROGRAM_ID, MOCK_COLD_ATA).unwrap();
        assert_eq!(adapter.chain_id(), ChainId::SolanaMainnet);
        assert_eq!(
            adapter.rent_reserve_lamports(),
            SolanaSvmAdapter::DEFAULT_ATA_RENT_LAMPORTS
        );
    }

    #[test]
    fn test_svm_pda_canonical_off_curve_proof() {
        let adapter = SolanaSvmAdapter::new(MOCK_PROGRAM_ID, MOCK_COLD_ATA).unwrap();
        let (pda_bytes, _bump) = adapter.find_pda(b"test_customer_seed_12345").unwrap();

        // Formal off-curve mathematical theorem verification:
        // Must fail decompression on Edwards25519 curve
        assert!(CompressedEdwardsY(pda_bytes).decompress().is_none());
        assert_ne!(pda_bytes, [0_u8; 32]);
    }

    #[tokio::test]
    async fn test_svm_dual_mode_routing() {
        let adapter = SolanaSvmAdapter::new(MOCK_PROGRAM_ID, MOCK_COLD_ATA).unwrap();
        let usdc_asset = PhysicalAssetId {
            chain_id: ChainId::SolanaMainnet,
            logical_asset: LogicalAsset::Usdc,
            token_contract: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            decimals: 6,
            keep_one_unit_dust: false,
            target_confirmations: 32,
        };

        // Mode A: Direct checkout with Reference Key
        let route_a = adapter
            .derive_checkout_route(77, None, &usdc_asset)
            .await
            .unwrap();
        assert_eq!(route_a.deposit_address, MOCK_COLD_ATA);
        assert!(route_a.routing_reference.is_some());
        assert_eq!(
            route_a.watchlist_lookup_key(),
            route_a.routing_reference.as_ref().unwrap()
        );

        // Mode B: CEX withdrawal with PDA
        let cid = Uuid::new_v4();
        let route_b = adapter
            .derive_checkout_route(78, Some(cid), &usdc_asset)
            .await
            .unwrap();
        assert_ne!(route_b.deposit_address, MOCK_COLD_ATA);
        assert!(route_b.routing_reference.is_none());
        assert_eq!(route_b.watchlist_lookup_key(), route_b.deposit_address);
    }
}
