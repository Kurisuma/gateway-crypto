//! # gw-chain-traits
//!
//! Enterprise polymorphic network adapter traits, standardized transaction envelopes,
//! consensus block indexer interfaces, and the multi-chain adapter registry.
//!
//! # Security & Architectural Invariants
//! - **Invariant I (Zero Private Keys):** Traits in this crate operate strictly on watch-only public
//!   material (zpubs, CREATE2 bytecode parameters, and reference keys). Unsigned payloads are emitted
//!   for isolated Zone C verification and signing.
//! - **Polymorphic Unified Architecture:** Enables unified gateway checkout, indexing, and treasury
//!   portfolio aggregation across all 8 networks without `match` branching.

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
use gw_primitives::{
    ChainArchitecture, ChainId, PhysicalAssetId, RawAssetAmount, SovereignError, WalletTier,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

/// Error taxonomy for multi-chain network adapter operations and RPC node communications.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Foundational mathematical, taxonomic, or domain invariant violation.
    #[error("Primitive domain error: {0}")]
    Primitive(#[from] SovereignError),

    /// RPC communication failure when querying native nodes.
    #[error("RPC node transport failure on chain {chain_id:?}: {reason}")]
    RpcTransport {
        /// Target chain.
        chain_id: ChainId,
        /// Failure details or response status.
        reason: String,
    },

    /// Chain reorganization detected by the parent-hash sliding window ring buffer.
    #[error("Chain reorganization detected at height {height}: expected parent {expected}, got {actual}")]
    ChainReorgDetected {
        /// Block height where fork occurred.
        height: u64,
        /// Expected parent block hash according to local canonical ledger.
        expected: String,
        /// Actual parent block hash reported by the node.
        actual: String,
    },

    /// Rotating guest deposit address pool exhausted under heavy checkout traffic.
    #[error("No available pre-computed addresses in rotating pool for chain {0:?}")]
    AddressPoolExhausted(ChainId),

    /// Accumulation below economical sweeping threshold (gas cost exceeds deposit value).
    #[error("Sweeping threshold not met: current={current_raw}, minimum={min_raw}")]
    BelowSweepThreshold {
        /// Current balance.
        current_raw: U256,
        /// Required minimum balance.
        min_raw: U256,
    },

    /// Destination address failed immutable whitelist verification in PreSignPolicyGuard.
    #[error("Security policy violation: destination address '{0}' is not in immutable whitelist")]
    UntrustedDestination(String),

    /// Gas relayer resource exhausted (e.g. TRON Energy or native fee balance).
    #[error("Gas relayer resource exhausted on chain {chain_id:?}: {details}")]
    RelayerExhausted {
        /// Chain ID.
        chain_id: ChainId,
        /// Resource details.
        details: String,
    },

    /// General adapter failure.
    #[error("Adapter operational error: {0}")]
    General(String),
}

/// Checkout routing instructions delivered to customer UI and registered in `gw-memcache`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckoutDepositRoute {
    /// Blockchain network for payment.
    pub chain_id: ChainId,
    /// Primary on-chain receiving address (BIP-84 bc1q, CREATE2 0x..., Tron T..., or single vault).
    pub deposit_address: String,
    /// Optional secondary routing key (Solana Reference Pubkey or TON Crockford Base32 Memo).
    pub routing_reference: Option<String>,
    /// Salt or derivation path locator for deterministic Zone C sweep reconstruction.
    pub derivation_locator: String,
}

impl CheckoutDepositRoute {
    /// Returns the exact lookup key used in `gw-memcache` for $O(1)$ transfer matching.
    pub fn watchlist_lookup_key(&self) -> &str {
        self.routing_reference
            .as_deref()
            .unwrap_or(&self.deposit_address)
    }
}

/// Chain-agnostic normalized transfer event emitted by native block indexers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedTransferEvent {
    /// Originating blockchain network.
    pub chain_id: ChainId,
    /// Execution architecture taxonomy.
    pub architecture: ChainArchitecture,
    /// Transaction hash.
    pub tx_hash: String,
    /// Block height / number.
    pub block_number: u64,
    /// Block hash.
    pub block_hash: String,
    /// Parent block hash for DAG continuity verification.
    pub parent_block_hash: String,
    /// Block timestamp in seconds since Unix epoch.
    pub block_timestamp_unix: u64,
    /// Matched lookup key (address, reference pubkey, or memo).
    pub lookup_key: String,
    /// Canonical lowercase contract address, or `"NATIVE"` for base gas coins.
    pub token_contract: String,
    /// Net token balance delta credited to the deposit route.
    pub net_amount_raw: RawAssetAmount,
    /// Gate 1: `true` if and only if the on-chain receipt executed successfully without revert.
    pub execution_succeeded: bool,
    /// Current number of block confirmations.
    pub confirmations: u32,
    /// Target confirmation depth required for finality.
    pub target_confirmations: u32,
}

/// Standardized unsigned transaction envelope passed to Zone C Enclave for policy checking and signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransactionEnvelope {
    /// Unique identifier for idempotency and anti-replay protection.
    pub envelope_id: Uuid,
    /// Target blockchain network.
    pub chain_id: ChainId,
    /// Target execution architecture.
    pub architecture: ChainArchitecture,
    /// Source wallet tier.
    pub source_tier: WalletTier,
    /// Destination wallet tier.
    pub destination_tier: WalletTier,
    /// Destination address (must match Zone C pinned whitelist).
    pub expected_destination_address: String,
    /// Asset specification.
    pub physical_asset: PhysicalAssetId,
    /// Exact amount to sweep or transfer.
    pub sweep_amount_raw: RawAssetAmount,
    /// Estimated gas or network fee.
    pub estimated_gas_fee_raw: RawAssetAmount,
    /// Raw unsigned payload bytes (PSBT, RLP, SVM Message, TON BOC, Sui BCS).
    pub raw_unsigned_payload: Vec<u8>,
    /// Derivation locator or CREATE2 salt for Zone C key derivation.
    pub signer_key_locator: String,
}

/// Dry-run simulation report verifying execution outcome prior to signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunSimulationReport {
    /// Whether simulation succeeded without revert or abort.
    pub simulation_succeeded: bool,
    /// Exact gas / computation units consumed.
    pub gas_consumed: u64,
    /// Net verified balance delta on target destination.
    pub verified_recipient_delta: RawAssetAmount,
    /// Revert or error reason if simulation failed.
    pub revert_reason: Option<String>,
}

/// Health and capacity metrics for Tier 1 Gas Relayer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerResourceHealth {
    /// Native gas coin balance.
    pub native_balance: RawAssetAmount,
    /// Staked TRON energy or SVM compute quota remaining.
    pub staked_energy_remaining: u64,
    /// Current on-chain nonce or sequence number.
    pub current_nonce: u64,
    /// Whether relayer has sufficient capacity to sponsor sweeps.
    pub is_healthy: bool,
}

/// Base trait providing chain identification and architecture taxonomy.
pub trait BlockchainAdapter: Send + Sync {
    /// Network identifier handled by this adapter.
    fn chain_id(&self) -> ChainId;

    /// Execution architecture taxonomy for this network.
    fn architecture(&self) -> ChainArchitecture {
        self.chain_id().architecture()
    }
}

/// Trait 1: Deterministic Watch-Only Address & Routing Derivation.
#[async_trait]
pub trait WatchOnlyAddressDeriver: BlockchainAdapter {
    /// Derives a deterministic checkout deposit route for a customer invoice.
    async fn derive_checkout_route(
        &self,
        invoice_id: u64,
        customer_id: Option<Uuid>,
        asset: &PhysicalAssetId,
    ) -> Result<CheckoutDepositRoute, AdapterError>;
}

/// Trait 2: Native Node Block Ingestion & $O(1)$ Watchlist Filtering.
#[async_trait]
pub trait NativeBlockIndexer: BlockchainAdapter {
    /// Scans a block for transfers matching the watched lookup keys.
    async fn scan_block_for_watched_transfers(
        &self,
        block_height: u64,
        watched_lookup_keys: &HashSet<String>,
    ) -> Result<Vec<NormalizedTransferEvent>, AdapterError>;

    /// Queries the latest finalized block height from the connected native node.
    async fn latest_canonical_height(&self) -> Result<u64, AdapterError>;
}

/// Trait 3: Unified On-Chain Balance & Gas Relayer Health Reader.
#[async_trait]
pub trait OnChainBalanceReader: BlockchainAdapter {
    /// Queries the finalized balance of an address for a specific asset.
    async fn get_balance_raw(
        &self,
        address: &str,
        asset: &PhysicalAssetId,
    ) -> Result<RawAssetAmount, AdapterError>;

    /// Inspects the operational health of the Tier 1 Gas Relayer for this chain.
    async fn inspect_gas_relayer_health(&self) -> Result<RelayerResourceHealth, AdapterError>;
}

/// Trait 4: Unsigned Sweep & Cross-Network Transfer Payload Builder.
#[async_trait]
pub trait UnsignedSweepBuilder: BlockchainAdapter {
    /// Builds an unsigned sweep or consolidation envelope.
    async fn build_unsigned_transfer(
        &self,
        source_address_or_locator: &str,
        destination_address: &str,
        source_tier: WalletTier,
        destination_tier: WalletTier,
        asset: &PhysicalAssetId,
        amount: RawAssetAmount,
    ) -> Result<UnsignedTransactionEnvelope, AdapterError>;

    /// Broadcasts signed raw transaction bytes to the network.
    async fn broadcast_signed_transaction(
        &self,
        signed_raw_bytes: &[u8],
    ) -> Result<String, AdapterError>;
}

/// Master Object-Oriented Polymorphic Trait combining all network capabilities.
pub trait UnifiedNetworkAdapter:
    WatchOnlyAddressDeriver + NativeBlockIndexer + OnChainBalanceReader + UnsignedSweepBuilder
{
}

/// Thread-safe registry holding all active blockchain adapters for unified iteration.
#[derive(Clone, Default)]
pub struct NetworkAdapterRegistry {
    adapters: BTreeMap<ChainId, Arc<dyn UnifiedNetworkAdapter>>,
}

impl NetworkAdapterRegistry {
    /// Creates an empty adapter registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a concrete unified network adapter.
    pub fn register(&mut self, adapter: Arc<dyn UnifiedNetworkAdapter>) {
        self.adapters.insert(adapter.chain_id(), adapter);
    }

    /// Looks up an adapter by chain ID.
    pub fn get(&self, chain_id: ChainId) -> Option<Arc<dyn UnifiedNetworkAdapter>> {
        self.adapters.get(&chain_id).cloned()
    }

    /// Iterates over all registered network adapters.
    pub fn all_adapters(&self) -> impl Iterator<Item = (&ChainId, &Arc<dyn UnifiedNetworkAdapter>)> {
        self.adapters.iter()
    }

    /// Returns the total number of registered blockchain network adapters.
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    /// Returns `true` if no adapters are registered.
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_checkout_deposit_route_lookup_key() {
        // Mode A: Reference pubkey takes precedence as lookup key
        let route_sol = CheckoutDepositRoute {
            chain_id: ChainId::SolanaMainnet,
            deposit_address: "VaultSolana11111111111111111111111111111111".to_string(),
            routing_reference: Some("RefKey99999999999999999999999999999999".to_string()),
            derivation_locator: "ref_pubkey_0".to_string(),
        };
        assert_eq!(
            route_sol.watchlist_lookup_key(),
            "RefKey99999999999999999999999999999999"
        );

        // Mode B: Regular address is the lookup key
        let route_evm = CheckoutDepositRoute {
            chain_id: ChainId::EthereumMainnet,
            deposit_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            routing_reference: None,
            derivation_locator: "salt_0x0001".to_string(),
        };
        assert_eq!(
            route_evm.watchlist_lookup_key(),
            "0x1234567890abcdef1234567890abcdef12345678"
        );
    }

    #[test]
    fn test_adapter_registry_lifecycle() {
        let registry = NetworkAdapterRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.get(ChainId::EthereumMainnet).is_none());
    }
}
