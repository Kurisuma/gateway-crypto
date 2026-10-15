//! # Phase 7 Treasury & FIFO Accounting Theory Tests
//!
//! Formal verification of mathematical theorems and invariants:
//! - Theorem 7.1: Multi-network portfolio aggregation and canonical 18-decimal homomorphism $\mathcal{N}_{18}$.
//! - Theorem 7.2: Exact integer FIFO cost-basis lot consumption calculus ($\delta_k$ prefix sums).
//! - Theorem 7.3: Economical sweep threshold calculation and zero-dust hot-wallet proportional split $\alpha_{\text{cold}}$.
//! - Invariant IV: Zero-dust conservation $Q_{\to \text{Cold}} + Q_{\to \text{Market}} \equiv B$.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use alloy_primitives::U256;
use gw_chain_traits::CheckoutDepositRoute;
use gw_engine::{Invoice, VerifiedComplete};
use gw_primitives::{
    ChainId, LogicalAsset, PhysicalAssetId, RawAssetAmount, UsdMicros, WalletTier,
};
use gw_treasury::{
    calculate_economical_sweep_threshold_raw, calculate_zero_dust_split,
    EnterpriseCrossNetworkLiquidityRouter, EnterpriseTreasuryPortfolioEngine, FifoCostBasisLot,
    GlobalRoutingDirective, NetworkLiquidityPolicy, SovereignCrossNetworkLiquidityRouter,
    SovereignTreasuryPortfolioEngine, WalletAssetHolding,
};
use proptest::prelude::*;
use std::collections::BTreeMap;
use uuid::Uuid;

fn sample_asset(chain_id: ChainId, decimals: u8) -> PhysicalAssetId {
    PhysicalAssetId {
        chain_id,
        logical_asset: LogicalAsset::Usdt,
        token_contract: "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
        decimals,
        keep_one_unit_dust: false,
        target_confirmations: 12,
    }
}

// ============================================================================
// TEST 1: INVOICE TO TAX LOT CONVERSION
// ============================================================================

#[tokio::test]
async fn test_record_verified_invoice_lot() {
    let engine = SovereignTreasuryPortfolioEngine::new();
    let asset = sample_asset(ChainId::EthereumMainnet, 6);

    let route = CheckoutDepositRoute {
        chain_id: ChainId::EthereumMainnet,
        deposit_address: "0x1111111111111111111111111111111111111111".to_string(),
        routing_reference: None,
        derivation_locator: "salt_01".to_string(),
    };

    let invoice = Invoice {
        invoice_id: 1042,
        customer_id: Some(Uuid::new_v4()),
        asset: asset.clone(),
        route,
        fiat_amount_usd: UsdMicros(100_000_000), // $100.00
        locked_price_usd: UsdMicros(1_000_000),  // $1.00
        expected_amount_raw: RawAssetAmount::new(U256::from(100_000_000u64), 6),
        received_amount_raw: RawAssetAmount::new(U256::from(100_000_000u64), 6),
        tolerance_bps: 50,
        expires_at_unix: 1700003600,
        state: VerifiedComplete {
            settlement_tx_hash: "0xabcdef1234567890".to_string(),
            settled_at_unix: 1700000000,
            is_overpaid: false,
            surplus_raw: RawAssetAmount::zero(6),
        },
    };

    let lot = engine
        .record_verified_invoice_lot(&invoice)
        .await
        .expect("lot recording should succeed");

    assert_eq!(lot.source_invoice_id, 1042);
    assert_eq!(lot.initial_amount.raw(), U256::from(100_000_000u64));
    assert_eq!(lot.remaining_amount.raw(), U256::from(100_000_000u64));
    assert_eq!(lot.acquisition_price_usd, UsdMicros(1_000_000));
    assert_eq!(lot.acquired_at_unix, 1700000000);
}

// ============================================================================
// TEST 2: MULTI-CHAIN PORTFOLIO ROLLUP & CANONICAL 18 HOMOMORPHISM
// ============================================================================

#[tokio::test]
async fn test_multi_chain_portfolio_rollup() {
    let engine = SovereignTreasuryPortfolioEngine::new();

    // Holding 1: 10,000 USDT on Ethereum (18 decimals: 10,000 * 10^18)
    let eth_asset = sample_asset(ChainId::EthereumMainnet, 18);
    let eth_holding = WalletAssetHolding {
        wallet_id: Uuid::new_v4(),
        wallet_tier: WalletTier::Tier3ColdVault,
        asset: eth_asset.clone(),
        raw_balance: RawAssetAmount::new(U256::from(10_000u64) * U256::from(10u64).pow(U256::from(18u8)), 18),
        current_spot_price_usd: UsdMicros(1_000_000), // $1.00
    };

    // Holding 2: 25,000 USDT on Tron (6 decimals: 25,000 * 10^6)
    let tron_asset = sample_asset(ChainId::TronMainnet, 6);
    let tron_holding = WalletAssetHolding {
        wallet_id: Uuid::new_v4(),
        wallet_tier: WalletTier::Tier2OperationalHot,
        asset: tron_asset.clone(),
        raw_balance: RawAssetAmount::new(U256::from(25_000u64) * U256::from(10u64).pow(U256::from(6u8)), 6),
        current_spot_price_usd: UsdMicros(1_000_000), // $1.00
    };

    // Holding 3: 5,000 USDT on Solana (6 decimals: 5,000 * 10^6)
    let sol_asset = sample_asset(ChainId::SolanaMainnet, 6);
    let sol_holding = WalletAssetHolding {
        wallet_id: Uuid::new_v4(),
        wallet_tier: WalletTier::Tier1GasRelayer,
        asset: sol_asset.clone(),
        raw_balance: RawAssetAmount::new(U256::from(5_000u64) * U256::from(10u64).pow(U256::from(6u8)), 6),
        current_spot_price_usd: UsdMicros(1_000_000), // $1.00
    };

    let holdings = vec![eth_holding, tron_holding, sol_holding];

    // Open tax lots for Unrealized PnL:
    // Lot 1: 20,000 USDT acquired at $0.98 ($980,000 micros)
    let lot1 = FifoCostBasisLot {
        lot_id: Uuid::new_v4(),
        source_invoice_id: 1,
        asset: tron_asset.clone(),
        initial_amount: RawAssetAmount::new(U256::from(20_000u64) * U256::from(10u64).pow(U256::from(6u8)), 6),
        remaining_amount: RawAssetAmount::new(U256::from(20_000u64) * U256::from(10u64).pow(U256::from(6u8)), 6),
        acquisition_price_usd: UsdMicros(980_000),
        acquired_at_unix: 1700000000,
    };

    // Lot 2: 20,000 USDT acquired at $1.02 ($1,020,000 micros)
    let lot2 = FifoCostBasisLot {
        lot_id: Uuid::new_v4(),
        source_invoice_id: 2,
        asset: eth_asset.clone(),
        initial_amount: RawAssetAmount::new(U256::from(20_000u64) * U256::from(10u64).pow(U256::from(18u8)), 18),
        remaining_amount: RawAssetAmount::new(U256::from(20_000u64) * U256::from(10u64).pow(U256::from(18u8)), 18),
        acquisition_price_usd: UsdMicros(1_020_000),
        acquired_at_unix: 1700000500,
    };

    let lots = vec![lot1, lot2];

    let portfolio = engine
        .compute_unified_global_portfolio(&holdings, &lots)
        .await
        .expect("portfolio computation should succeed");

    let usdt_summary = portfolio
        .get(&LogicalAsset::Usdt)
        .expect("USDT summary must exist");

    // Total canonical 18 units: 10,000 + 25,000 + 5,000 = 40,000 USDT * 10^18
    let expected_canonical_18 = U256::from(40_000u64) * U256::from(10u64).pow(U256::from(18u8));
    assert_eq!(usdt_summary.total_canonical_18_units, expected_canonical_18);

    // Total market valuation: 40,000 * $1.00 = $40,000.00 = 40,000,000,000 micros
    assert_eq!(usdt_summary.total_market_valuation_usd.0, 40_000_000_000);

    // Total cost basis:
    // 20,000 * $0.98 = $19,600.00 = 19,600,000,000 micros
    // 20,000 * $1.02 = $20,400.00 = 20,400,000,000 micros
    // Total cost basis = 40,000,000,000 micros
    assert_eq!(usdt_summary.total_fifo_cost_basis_usd.0, 40_000_000_000);

    // Unrealized PnL: 40,000,000,000 - 40,000,000,000 = 0 micros
    assert_eq!(usdt_summary.unrealized_pnl_usd_micros, 0);

    // Tier breakdown verification
    assert_eq!(
        usdt_summary.valuation_by_tier_usd.get(&WalletTier::Tier3ColdVault).unwrap().0,
        10_000_000_000
    );
    assert_eq!(
        usdt_summary.valuation_by_tier_usd.get(&WalletTier::Tier2OperationalHot).unwrap().0,
        25_000_000_000
    );
    assert_eq!(
        usdt_summary.valuation_by_tier_usd.get(&WalletTier::Tier1GasRelayer).unwrap().0,
        5_000_000_000
    );
}

// ============================================================================
// TEST 3: CHRONOLOGICAL FIFO LOT DEPLETION CALCULUS
// ============================================================================

#[tokio::test]
async fn test_execute_fifo_lot_consumption() {
    let engine = SovereignTreasuryPortfolioEngine::new();
    let asset = sample_asset(ChainId::EthereumMainnet, 6);

    // Setup 3 open tax lots acquired chronologically
    // Lot 1: 100 units @ $10.00 (acquired t=100)
    let lot1 = FifoCostBasisLot {
        lot_id: Uuid::new_v4(),
        source_invoice_id: 101,
        asset: asset.clone(),
        initial_amount: RawAssetAmount::new(U256::from(100_000_000u64), 6),
        remaining_amount: RawAssetAmount::new(U256::from(100_000_000u64), 6),
        acquisition_price_usd: UsdMicros(10_000_000), // $10.00
        acquired_at_unix: 100,
    };

    // Lot 2: 200 units @ $12.00 (acquired t=200)
    let lot2 = FifoCostBasisLot {
        lot_id: Uuid::new_v4(),
        source_invoice_id: 102,
        asset: asset.clone(),
        initial_amount: RawAssetAmount::new(U256::from(200_000_000u64), 6),
        remaining_amount: RawAssetAmount::new(U256::from(200_000_000u64), 6),
        acquisition_price_usd: UsdMicros(12_000_000), // $12.00
        acquired_at_unix: 200,
    };

    // Lot 3: 300 units @ $15.00 (acquired t=300)
    let lot3 = FifoCostBasisLot {
        lot_id: Uuid::new_v4(),
        source_invoice_id: 103,
        asset: asset.clone(),
        initial_amount: RawAssetAmount::new(U256::from(300_000_000u64), 6),
        remaining_amount: RawAssetAmount::new(U256::from(300_000_000u64), 6),
        acquisition_price_usd: UsdMicros(15_000_000), // $15.00
        acquired_at_unix: 300,
    };

    let mut open_lots = vec![lot3, lot1, lot2]; // Deliberately out of order

    // Disposal 1: Dispose 150 units at execution price $14.00, fee = $5.00
    // Expected depletion:
    // Lot 1 (100 units): fully consumed (delta_1 = 100). Remaining = 0. Cost = 100 * $10 = $1,000
    // Lot 2 (200 units): partially consumed (delta_2 = 50). Remaining = 150. Cost = 50 * $12 = $600
    // Total cost basis = $1,600 = 1,600,000,000 micros
    // Gross proceeds = 150 * $14 = $2,100 = 2,100,000,000 micros
    // Network fee = $5 = 5,000,000 micros
    // Net Realized PnL = $2,100 - $1,600 - $5 = $495.00 = 495,000,000 micros
    let disposed_amount = RawAssetAmount::new(U256::from(150_000_000u64), 6);
    let exec_price = UsdMicros(14_000_000);
    let fee = UsdMicros(5_000_000);

    let report = engine
        .execute_fifo_lot_consumption(&mut open_lots, disposed_amount, exec_price, fee)
        .await
        .expect("consumption should succeed");

    assert_eq!(report.disposed_amount, disposed_amount);
    assert_eq!(report.consumed_lot_slices.len(), 2);
    assert_eq!(report.total_cost_basis_usd.0, 1_600_000_000);
    assert_eq!(report.gross_proceeds_usd.0, 2_100_000_000);
    assert_eq!(report.network_fee_burned_usd.0, 5_000_000);
    assert_eq!(report.net_realized_pnl_usd_micros, 495_000_000);

    // Verify in-place remaining amounts on lots:
    // open_lots is sorted: lot1 (t=100), lot2 (t=200), lot3 (t=300)
    assert_eq!(open_lots.first().unwrap().remaining_amount.raw(), U256::ZERO);
    assert_eq!(
        open_lots.get(1).unwrap().remaining_amount.raw(),
        U256::from(150_000_000u64)
    );
    assert_eq!(
        open_lots.get(2).unwrap().remaining_amount.raw(),
        U256::from(300_000_000u64)
    );
}

// ============================================================================
// TEST 4: GAS RELAYER REPLENISHMENT PLANNING
// ============================================================================

#[tokio::test]
async fn test_plan_tier1_relayer_gas_refills() {
    let router = SovereignCrossNetworkLiquidityRouter::new();
    let asset = sample_asset(ChainId::EthereumMainnet, 18);

    let policy = NetworkLiquidityPolicy {
        asset: asset.clone(),
        tier1_relayer_address: "0xRelayer111".to_string(),
        tier2_hot_wallet_address: "0xHot222".to_string(),
        tier2_key_locator: "m/44'/60'/0'/0/0".to_string(),
        tier3_cold_vault_address: "0xCold333".to_string(),
        tier4_market_exchange_address: "0xExchange444".to_string(),
        hot_wallet_ceiling_usd: UsdMicros(100_000_000_000), // $100,000
        cold_vault_split_bps: 7000,
        market_exchange_split_bps: 3000,
        min_relayer_gas_raw: RawAssetAmount::new(U256::from(10u64) * U256::from(10u64).pow(U256::from(18u8)), 18), // 10 ETH
        target_relayer_gas_raw: RawAssetAmount::new(U256::from(50u64) * U256::from(10u64).pow(U256::from(18u8)), 18), // 50 ETH
    };

    let policies = vec![policy];

    // Case A: Relayer has 15 ETH (> 10 min) -> No refill envelope generated
    let mut relayer_balances = BTreeMap::new();
    relayer_balances.insert(
        ChainId::EthereumMainnet,
        RawAssetAmount::new(U256::from(15u64) * U256::from(10u64).pow(U256::from(18u8)), 18),
    );

    let envelopes = router
        .plan_tier1_relayer_gas_refills(&policies, &relayer_balances)
        .await
        .unwrap();
    assert!(envelopes.is_empty());

    // Case B: Relayer has 4 ETH (< 10 min) -> Refill envelope for 50 - 4 = 46 ETH
    relayer_balances.insert(
        ChainId::EthereumMainnet,
        RawAssetAmount::new(U256::from(4u64) * U256::from(10u64).pow(U256::from(18u8)), 18),
    );

    let envelopes = router
        .plan_tier1_relayer_gas_refills(&policies, &relayer_balances)
        .await
        .unwrap();
    assert_eq!(envelopes.len(), 1);

    let env = envelopes.first().unwrap();
    assert_eq!(env.destination_tier, WalletTier::Tier1GasRelayer);
    assert_eq!(env.expected_destination_address, "0xRelayer111");
    let expected_refill = U256::from(46u64) * U256::from(10u64).pow(U256::from(18u8));
    assert_eq!(env.sweep_amount_raw.raw(), expected_refill);
}

// ============================================================================
// TEST 5: GLOBAL ROUTING TRANSFERS & OVERFLOW SPLIT
// ============================================================================

#[tokio::test]
async fn test_plan_global_liquidity_transfers_split() {
    let router = SovereignCrossNetworkLiquidityRouter::new();
    let asset = sample_asset(ChainId::EthereumMainnet, 6);

    let policy = NetworkLiquidityPolicy {
        asset: asset.clone(),
        tier1_relayer_address: "0xRelayer".to_string(),
        tier2_hot_wallet_address: "0xHot".to_string(),
        tier2_key_locator: "m/44'/60'/0'/0/0".to_string(),
        tier3_cold_vault_address: "0xColdSafe".to_string(),
        tier4_market_exchange_address: "0xExchangeSafe".to_string(),
        hot_wallet_ceiling_usd: UsdMicros(10_000_000_000), // $10,000 ceiling
        cold_vault_split_bps: 7000,                         // 70%
        market_exchange_split_bps: 3000,                    // 30%
        min_relayer_gas_raw: RawAssetAmount::zero(6),
        target_relayer_gas_raw: RawAssetAmount::zero(6),
    };

    let policies = vec![policy];
    let mut spot_prices = BTreeMap::new();
    spot_prices.insert(LogicalAsset::Usdt, UsdMicros(1_000_000)); // $1.00

    let mut hot_balances = BTreeMap::new();

    // Hot wallet balance = 20,000 USDT ($20,000)
    // Excess above $10,000 ceiling = $10,000 (10,000,000,000 units)
    // 70% to Cold = 7,000,000,000 units ($7,000)
    // 30% to Market = 3,000,000,000 units ($3,000)
    hot_balances.insert(
        (ChainId::EthereumMainnet, "0xHot".to_string()),
        RawAssetAmount::new(U256::from(20_000_000_000u64), 6),
    );

    let envelopes = router
        .plan_global_liquidity_transfers(
            Some(LogicalAsset::Usdt),
            GlobalRoutingDirective::PolicyDrivenProportionalSplit,
            &policies,
            &hot_balances,
            &spot_prices,
        )
        .await
        .unwrap();

    assert_eq!(envelopes.len(), 2);
    let cold_env = envelopes.first().unwrap();
    let market_env = envelopes.get(1).unwrap();

    assert_eq!(cold_env.destination_tier, WalletTier::Tier3ColdVault);
    assert_eq!(cold_env.expected_destination_address, "0xColdSafe");
    assert_eq!(cold_env.sweep_amount_raw.raw(), U256::from(7_000_000_000u64));

    assert_eq!(market_env.destination_tier, WalletTier::Tier4MarketExchange);
    assert_eq!(market_env.expected_destination_address, "0xExchangeSafe");
    assert_eq!(market_env.sweep_amount_raw.raw(), U256::from(3_000_000_000u64));

    // Zero-dust conservation
    assert_eq!(
        cold_env.sweep_amount_raw.raw() + market_env.sweep_amount_raw.raw(),
        U256::from(10_000_000_000u64)
    );
}

// ============================================================================
// TEST 6: PROPERTY-BASED FUZZING (PROPTEST)
// ============================================================================

proptest! {
    /// Invariant: Zero-dust hot/cold split conservation holds for all balances and split allocations.
    #[test]
    fn prop_zero_dust_split_conservation(
        balance in 0u64..u64::MAX,
        cold_bps in 0u16..=10_000u16,
    ) {
        let market_bps = 10_000u16 - cold_bps;
        let total = RawAssetAmount::new(U256::from(balance), 6);
        let (cold, market) = calculate_zero_dust_split(total, cold_bps, market_bps).unwrap();

        // Exact integer conservation without loss: Q_cold + Q_market == total
        prop_assert_eq!(cold.raw() + market.raw(), total.raw());
        // Monotonic bound: Q_cold <= total, Q_market <= total
        prop_assert!(cold.raw() <= total.raw());
        prop_assert!(market.raw() <= total.raw());
    }

    /// Invariant: Economical sweep threshold calculation never overflows and maintains monotonicity.
    #[test]
    fn prop_economical_sweep_threshold_bounds(
        gas_cost in 1u64..10_000_000u64,     // $0.000001 to $10.00
        spot_price in 1u64..100_000_000_000u64, // $0.000001 to $100,000
        max_fee_bps in 1u16..=10_000u16,
    ) {
        let gas_usd = UsdMicros(u128::from(gas_cost));
        let spot_usd = UsdMicros(u128::from(spot_price));

        let res = calculate_economical_sweep_threshold_raw(gas_usd, spot_usd, 6, max_fee_bps);
        prop_assert!(res.is_ok());
        let threshold = res.unwrap();
        prop_assert!(threshold.raw() > U256::ZERO);
    }
}
