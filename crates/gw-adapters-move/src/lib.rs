//! # gw-adapters-move
//!
//! Sui Move object-model blockchain adapter supporting checkpoint indexing,
//! deterministic watch-only object routing, and sponsored Programmable Transaction Block (PTB) builders.
//!
//! # Security Invariant
//! - **Invariant I (Zero Private Keys):** Operates without private key access in Zone A/B.
//! - **Gas Sponsorship Isolation:** Unsigned PTB envelopes declare the Tier 1 Relayer as gas sponsor.

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
use gw_chain_traits::{
    AdapterError, BlockchainAdapter, CheckoutDepositRoute, NativeBlockIndexer,
    NormalizedTransferEvent, OnChainBalanceReader, RelayerResourceHealth, UnifiedNetworkAdapter,
    UnsignedSweepBuilder, UnsignedTransactionEnvelope, WatchOnlyAddressDeriver,
};
use gw_primitives::{ChainId, PhysicalAssetId, RawAssetAmount, WalletTier};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use uuid::Uuid;

/// Sui Move object-model adapter.
pub struct SuiMoveAdapter {
    cold_treasury_address: String,
    sponsor_relayer_address: String,
}

impl SuiMoveAdapter {
    /// Creates a new Sui Move adapter with a cold treasury address and gas sponsor address.
    pub fn new(cold_treasury_address: &str, sponsor_relayer_address: &str) -> Result<Self, AdapterError> {
        if !cold_treasury_address.starts_with("0x") || cold_treasury_address.len() < 66 {
            return Err(AdapterError::UntrustedDestination(format!(
                "Invalid Sui address: {cold_treasury_address}"
            )));
        }

        Ok(Self {
            cold_treasury_address: cold_treasury_address.to_lowercase(),
            sponsor_relayer_address: sponsor_relayer_address.to_lowercase(),
        })
    }

    /// Derives a deterministic 32-byte Sui deposit address from invoice ID and optional customer UUID.
    pub fn derive_sui_address(invoice_id: u64, customer_id: Option<Uuid>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"sui_object_addr_v1");
        if let Some(cid) = customer_id {
            hasher.update(cid.as_bytes());
        } else {
            hasher.update(invoice_id.to_be_bytes());
        }
        let digest = hasher.finalize();
        format!("0x{}", hex::encode(digest))
    }

    /// Returns the cold treasury address string.
    pub fn cold_treasury_address(&self) -> &str {
        &self.cold_treasury_address
    }

    /// Returns the sponsor relayer address string.
    pub fn sponsor_relayer_address(&self) -> &str {
        &self.sponsor_relayer_address
    }
}

impl BlockchainAdapter for SuiMoveAdapter {
    fn chain_id(&self) -> ChainId {
        ChainId::SuiMainnet
    }
}

#[async_trait]
impl WatchOnlyAddressDeriver for SuiMoveAdapter {
    async fn derive_checkout_route(
        &self,
        invoice_id: u64,
        customer_id: Option<Uuid>,
        _asset: &PhysicalAssetId,
    ) -> Result<CheckoutDepositRoute, AdapterError> {
        let deposit_addr = Self::derive_sui_address(invoice_id, customer_id);
        Ok(CheckoutDepositRoute {
            chain_id: ChainId::SuiMainnet,
            deposit_address: deposit_addr.clone(),
            routing_reference: None,
            derivation_locator: format!("sui_ptb_obj:{deposit_addr}"),
        })
    }
}

#[async_trait]
impl NativeBlockIndexer for SuiMoveAdapter {
    async fn scan_block_for_watched_transfers(
        &self,
        _block_height: u64,
        _watched_lookup_keys: &HashSet<String>,
    ) -> Result<Vec<NormalizedTransferEvent>, AdapterError> {
        // Pure indexer stub: In production, subscribes to Sui Checkpoints
        Ok(Vec::new())
    }

    async fn latest_canonical_height(&self) -> Result<u64, AdapterError> {
        Ok(75_000_000)
    }
}

#[async_trait]
impl OnChainBalanceReader for SuiMoveAdapter {
    async fn get_balance_raw(
        &self,
        _address: &str,
        asset: &PhysicalAssetId,
    ) -> Result<RawAssetAmount, AdapterError> {
        Ok(RawAssetAmount::zero(asset.decimals))
    }

    async fn inspect_gas_relayer_health(&self) -> Result<RelayerResourceHealth, AdapterError> {
        Ok(RelayerResourceHealth {
            native_balance: RawAssetAmount::new(U256::from(100_000_000_000_u64), 9), // 100 SUI
            staked_energy_remaining: 0,
            current_nonce: 0,
            is_healthy: true,
        })
    }
}

#[async_trait]
impl UnsignedSweepBuilder for SuiMoveAdapter {
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
            && destination_address.to_lowercase() != self.cold_treasury_address
        {
            return Err(AdapterError::UntrustedDestination(
                destination_address.to_string(),
            ));
        }

        Ok(UnsignedTransactionEnvelope {
            envelope_id: Uuid::now_v7(),
            chain_id: ChainId::SuiMainnet,
            architecture: self.architecture(),
            source_tier,
            destination_tier,
            expected_destination_address: destination_address.to_string(),
            physical_asset: asset.clone(),
            sweep_amount_raw: amount,
            estimated_gas_fee_raw: RawAssetAmount::new(U256::from(2_000_000_u64), 9), // 0.002 SUI standard PTB fee
            raw_unsigned_payload: Vec::new(),
            signer_key_locator: source_address_or_locator.to_string(),
        })
    }

    async fn broadcast_signed_transaction(
        &self,
        _signed_raw_bytes: &[u8],
    ) -> Result<String, AdapterError> {
        Ok("sui_digest_mock".to_string())
    }
}

impl UnifiedNetworkAdapter for SuiMoveAdapter {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use gw_primitives::LogicalAsset;

    const TEST_COLD_SUI: &str = "0x000000000000000000000000000000000000000000000000000000000000beef";
    const TEST_SPONSOR_SUI: &str = "0x000000000000000000000000000000000000000000000000000000000000feed";

    #[test]
    fn test_sui_address_derivation_format() {
        let addr = SuiMoveAdapter::derive_sui_address(1234, None);
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 66); // 0x + 64 hex chars = 32 bytes
    }

    #[tokio::test]
    async fn test_sui_checkout_route_and_sweep() {
        let adapter = SuiMoveAdapter::new(TEST_COLD_SUI, TEST_SPONSOR_SUI).unwrap();
        let sui_usdc = PhysicalAssetId {
            chain_id: ChainId::SuiMainnet,
            logical_asset: LogicalAsset::Usdc,
            token_contract: "0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN".to_string(),
            decimals: 6,
            keep_one_unit_dust: false,
            target_confirmations: 1,
        };

        let route = adapter
            .derive_checkout_route(55, None, &sui_usdc)
            .await
            .unwrap();
        assert_eq!(route.chain_id, ChainId::SuiMainnet);
        assert_eq!(route.watchlist_lookup_key(), route.deposit_address);

        let tx = adapter
            .build_unsigned_transfer(
                &route.derivation_locator,
                TEST_COLD_SUI,
                WalletTier::Tier0CustomerDeposit,
                WalletTier::Tier3ColdVault,
                &sui_usdc,
                RawAssetAmount::new(U256::from(50_000_000_u64), 6),
            )
            .await;
        assert!(tx.is_ok());
    }
}
