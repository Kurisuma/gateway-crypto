//! # Multi-Chain Polymorphic Network Adapter Integration Suite
//!
//! Verifies complete object-oriented polymorphism across all 8 supported blockchain networks
//! using `NetworkAdapterRegistry` and `Arc<dyn UnifiedNetworkAdapter>`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use alloy_primitives::{Address, B256};
use gw_adapters_btc::BitcoinMainnetAdapter;
use gw_adapters_evm::EvmCreate2Adapter;
use gw_adapters_move::SuiMoveAdapter;
use gw_adapters_svm::SolanaSvmAdapter;
use gw_adapters_ton::TonActorAdapter;
use gw_adapters_tvm::TronTvmAdapter;
use gw_chain_traits::NetworkAdapterRegistry;
use gw_primitives::{ChainId, LogicalAsset, PhysicalAssetId};
use std::sync::Arc;
use uuid::Uuid;

const BTC_XPUB: &str = "xpub661MyMwAqRbcEtUEgdXRTY6dJQG9fRgs7C5QomqETKMYBJVtSGpRqyHSmhWy8snovPd5oWZgQ14zUquxbxu7Z1umuXbN5VDpUL1QobD5xUY";
const BTC_COLD: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

const EVM_FACTORY: Address = Address::repeat_byte(0x22);
const EVM_INIT_HASH: B256 = B256::repeat_byte(0x33);
const EVM_COLD: Address = Address::repeat_byte(0x88);

const SOL_PROGRAM_ID: &str = "11111111111111111111111111111111";
const SOL_COLD_ATA: &str = "7XJ9DkCkg3r297a7N64k8bQ57GfCqP37vGZpS65P3yHw";

const TRON_FACTORY: [u8; 20] = [0x41; 20];
const TRON_INIT_HASH: B256 = B256::repeat_byte(0x44);
const TRON_COLD: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

const TON_VAULT: &str = "EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N";
const TON_SCHEDULE: [u32; 4] = [0x11111, 0x22222, 0x33333, 0x44444];

const SUI_COLD: &str = "0x000000000000000000000000000000000000000000000000000000000000cafe";
const SUI_SPONSOR: &str = "0x000000000000000000000000000000000000000000000000000000000000fade";

fn build_populated_registry() -> NetworkAdapterRegistry {
    let mut registry = NetworkAdapterRegistry::new();

    // 1. Bitcoin
    let btc_adapter = Arc::new(BitcoinMainnetAdapter::new(BTC_XPUB, BTC_COLD, 3).unwrap());
    registry.register(btc_adapter);

    // 2. Ethereum Mainnet
    let eth_adapter = Arc::new(EvmCreate2Adapter::new(
        ChainId::EthereumMainnet,
        EVM_FACTORY,
        EVM_INIT_HASH,
        EVM_COLD,
        false,
    ));
    registry.register(eth_adapter);

    // 3. BNB Chain
    let bnb_adapter = Arc::new(EvmCreate2Adapter::new(
        ChainId::BnbChain,
        EVM_FACTORY,
        EVM_INIT_HASH,
        EVM_COLD,
        false,
    ));
    registry.register(bnb_adapter);

    // 4. Plume Mainnet
    let plume_adapter = Arc::new(EvmCreate2Adapter::new(
        ChainId::PlumeMainnet,
        EVM_FACTORY,
        EVM_INIT_HASH,
        EVM_COLD,
        false,
    ));
    registry.register(plume_adapter);

    // 5. Solana Mainnet
    let sol_adapter = Arc::new(SolanaSvmAdapter::new(SOL_PROGRAM_ID, SOL_COLD_ATA).unwrap());
    registry.register(sol_adapter);

    // 6. TRON Mainnet
    let tron_adapter = Arc::new(TronTvmAdapter::new(TRON_FACTORY, TRON_INIT_HASH, TRON_COLD).unwrap());
    registry.register(tron_adapter);

    // 7. TON Mainnet
    let ton_adapter = Arc::new(TonActorAdapter::new(TON_VAULT, TON_SCHEDULE).unwrap());
    registry.register(ton_adapter);

    // 8. Sui Mainnet
    let sui_adapter = Arc::new(SuiMoveAdapter::new(SUI_COLD, SUI_SPONSOR).unwrap());
    registry.register(sui_adapter);

    registry
}

#[tokio::test]
async fn test_polymorphic_coverage_all_8_networks() {
    let registry = build_populated_registry();
    assert_eq!(registry.len(), 8);

    let all_chains = [
        ChainId::BitcoinMainnet,
        ChainId::EthereumMainnet,
        ChainId::BnbChain,
        ChainId::PlumeMainnet,
        ChainId::SolanaMainnet,
        ChainId::TronMainnet,
        ChainId::TonMainnet,
        ChainId::SuiMainnet,
    ];

    let invoice_id = 9999_u64;
    let customer_id = Uuid::new_v4();

    for chain in all_chains {
        let adapter = registry.get(chain).expect("Adapter must be registered");
        assert_eq!(adapter.chain_id(), chain);

        let asset = PhysicalAssetId {
            chain_id: chain,
            logical_asset: LogicalAsset::Usdt,
            token_contract: "TEST".to_string(),
            decimals: LogicalAsset::Usdt.default_decimals(),
            keep_one_unit_dust: chain == ChainId::TronMainnet,
            target_confirmations: 1,
        };

        // Polymorphic checkout route derivation without match statement:
        let route = adapter
            .derive_checkout_route(invoice_id, Some(customer_id), &asset)
            .await
            .expect("Checkout route derivation must succeed");

        assert_eq!(route.chain_id, chain);
        assert!(!route.deposit_address.is_empty());
        assert!(!route.derivation_locator.is_empty());

        // Format checks per architecture
        match chain {
            ChainId::BitcoinMainnet => assert!(route.deposit_address.starts_with("bc1q")),
            ChainId::EthereumMainnet | ChainId::BnbChain | ChainId::PlumeMainnet => {
                assert!(route.deposit_address.starts_with("0x"));
                assert_eq!(route.deposit_address.len(), 42);
            }
            ChainId::SolanaMainnet => {
                // With customer_id provided, Mode B PDA address is returned
                assert!(!route.deposit_address.is_empty());
            }
            ChainId::TronMainnet => {
                assert!(route.deposit_address.starts_with('T'));
                assert_eq!(route.deposit_address.len(), 34);
            }
            ChainId::TonMainnet => {
                assert_eq!(route.deposit_address, TON_VAULT);
                assert!(route.routing_reference.is_some());
                assert_eq!(route.routing_reference.unwrap().len(), 8);
            }
            ChainId::SuiMainnet => {
                assert!(route.deposit_address.starts_with("0x"));
                assert_eq!(route.deposit_address.len(), 66);
            }
        }

        // Polymorphic relayer health audit
        let relayer_health = adapter
            .inspect_gas_relayer_health()
            .await
            .expect("Gas relayer health must be readable");
        assert!(relayer_health.is_healthy);

        // Polymorphic block height query
        let height = adapter
            .latest_canonical_height()
            .await
            .expect("Canonical height must be readable");
        assert!(height > 0);
    }
}
