//! # Mathematical Theory Formal Verification Suite
//!
//! Rigorous test suite implementing and verifying the formal mathematical theorems,
//! fixed-point algebraic homomorphisms, 5-Gate state transitions, FIFO prefix depletion calculus,
//! and Erlang-B queueing bounds specified in:
//! - `UNIFIED_RUST_CRYPTO_GATEWAY_AND_TREASURY_SPEC_THEORY.md` (V5.0 Formal)
//! - `ENTERPRISE_IN_MEMORY_CACHE_SPEC_THEORY.md` (IMPRCE Sovereign Theory)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::assign_op_pattern,
    clippy::float_arithmetic
)]

use alloy_primitives::U256;
use gw_primitives::{
    CachePriorityTier, ChainId, LogicalAsset, PhysicalAssetId, RawAssetAmount,
    SovereignError, UsdMicros,
};
use proptest::prelude::*;

// ============================================================================
// THEOREM 1: Canonical 18-Decimal Normalization Homomorphism N_18(r, d)
// Theory Spec §3.1 eq (196-199)
//
// Theorem (Linear Homomorphism):
// For all d <= 18 and all r_1, r_2 in Z_{2^256} such that r_1 + r_2 does not overflow,
//   N_18(r_1 + r_2, d) == N_18(r_1, d) + N_18(r_2, d)
// ============================================================================

#[test]
fn test_theorem_1_linear_homomorphism_n18() {
    let test_cases = vec![
        // 6 decimals (USDT, USDC on Tron / Ethereum)
        (U256::from(1_500_000_u64), U256::from(2_500_000_u64), 6),
        // 8 decimals (BTC on Bitcoin)
        (U256::from(50_000_000_u64), U256::from(75_000_000_u64), 8),
        // 9 decimals (SOL on Solana, SUI on Sui, TON on TON)
        (U256::from(100_000_000_u64), U256::from(900_000_000_u64), 9),
        // 18 decimals (ETH on Ethereum, BNB on BSC, PLUME on Plume)
        (
            U256::from(1_000_000_000_000_000_000_u128),
            U256::from(3_000_000_000_000_000_000_u128),
            18,
        ),
    ];

    for (r1, r2, d) in test_cases {
        let amt1 = RawAssetAmount::new(r1, d);
        let amt2 = RawAssetAmount::new(r2, d);
        let sum_raw = amt1.checked_add(amt2).expect("checked add").to_canonical_18().expect("n18 sum");

        let n1 = amt1.to_canonical_18().expect("n18 amt1");
        let n2 = amt2.to_canonical_18().expect("n18 amt2");
        let direct_sum = n1.checked_add(n2).expect("direct sum");

        assert_eq!(
            sum_raw, direct_sum,
            "Failed Linear Homomorphism N_18(r1 + r2, {d}) == N_18(r1, {d}) + N_18(r2, {d})"
        );
    }
}

proptest! {
    /// Property-based verification that N_18(r, d) preserves linearity for arbitrary 64-bit inputs
    #[test]
    fn prop_test_homomorphism_linearity(r1_u64 in 1_u64..1_000_000_000, r2_u64 in 1_u64..1_000_000_000, d in 0_u8..=18_u8) {
        let amt1 = RawAssetAmount::new(U256::from(r1_u64), d);
        let amt2 = RawAssetAmount::new(U256::from(r2_u64), d);

        let sum = amt1.checked_add(amt2).unwrap();
        let lhs = sum.to_canonical_18().unwrap();
        let rhs = amt1.to_canonical_18().unwrap().checked_add(amt2.to_canonical_18().unwrap()).unwrap();

        prop_assert_eq!(lhs, rhs);
    }
}

// ============================================================================
// THEOREM 2: Exact USD Valuation Mapping V_USD(r, d, P_mu)
// Theory Spec §3.1 eq (201-202)
//
// V_USD(r, d, P_mu) = floor((r * P_mu) / 10^d)
// ============================================================================

#[test]
fn test_theorem_2_exact_usd_valuation() {
    // Case A: 2.5 BTC (d=8) at $65,000.00 -> P_mu = 65_000_000_000 micros
    // r = 250_000_000 raw satoshis
    // Expected USD = 2.5 * 65_000 = $162,500.00 = 162_500_000_000 micros
    let btc = RawAssetAmount::new(U256::from(250_000_000_u64), 8);
    let btc_price = UsdMicros(65_000 * UsdMicros::SCALE);
    let val_btc = UsdMicros::from_raw_asset_amount(btc, btc_price).expect("valid valuation");
    assert_eq!(val_btc.0, 162_500 * UsdMicros::SCALE);

    // Case B: 100.50 USDT (d=6) at $1.00 -> P_mu = 1_000_000 micros
    // r = 100_500_000 raw
    // Expected USD = $100.50 = 100_500_000 micros
    let usdt = RawAssetAmount::new(U256::from(100_500_000_u64), 6);
    let usdt_price = UsdMicros(1 * UsdMicros::SCALE);
    let val_usdt = UsdMicros::from_raw_asset_amount(usdt, usdt_price).expect("valid valuation");
    assert_eq!(val_usdt.0, 100_500_000);

    // Case C: 0.04 ETH (d=18) at $2,500.00 -> P_mu = 2_500_000_000 micros
    // r = 40_000_000_000_000_000 raw
    // Expected USD = 0.04 * 2500 = $100.00 = 100_000_000 micros
    let eth = RawAssetAmount::new(U256::from(40_000_000_000_000_000_u64), 18);
    let eth_price = UsdMicros(2_500 * UsdMicros::SCALE);
    let val_eth = UsdMicros::from_raw_asset_amount(eth, eth_price).expect("valid valuation");
    assert_eq!(val_eth.0, 100 * UsdMicros::SCALE);
}

// ============================================================================
// THEOREM 3: Dual-Oracle Deviation Guard delta_bps and Circuit Breaker
// Theory Spec §3.2 eq (208-211)
//
// delta_bps(P_cex, P_chain) = floor((|P_cex - P_chain| * 10,000) / min(P_cex, P_chain))
// Circuit breaker halts if delta_bps > 150 bps
// ============================================================================

#[test]
fn test_theorem_3_dual_oracle_deviation_boundary() {
    let p_base = UsdMicros(1_000 * UsdMicros::SCALE); // $1,000.00

    // Exactly 150 bps deviation (+1.5%):
    // min = 1,000_000_000. diff = 15_000_000 (150 bps).
    let p_upper_150 = UsdMicros(1_015 * UsdMicros::SCALE);
    let passed = UsdMicros::verify_dual_oracle_price(p_base, p_upper_150, 150)
        .expect("150 bps boundary should pass");
    assert_eq!(passed, p_base); // Conservative minimum

    // 151 bps deviation (+1.51%): diff = 15_100_000 -> 151 bps > 150 bps max
    let p_upper_151 = UsdMicros(1_015_100_000);
    let err = UsdMicros::verify_dual_oracle_price(p_base, p_upper_151, 150)
        .expect_err("151 bps must trip circuit breaker");
    assert!(matches!(
        err,
        SovereignError::OracleDivergenceCircuitBreaker {
            divergence_bps: 151,
            max_bps: 150,
            ..
        }
    ));

    // Reverse direction (P_cex > P_chain):
    // If P_chain = 1000, P_cex = 1015, min = 1000, diff = 15 -> 150 bps passes
    let passed_rev = UsdMicros::verify_dual_oracle_price(p_upper_150, p_base, 150)
        .expect("symmetric deviation passes");
    assert_eq!(passed_rev, p_base);
}

// ============================================================================
// THEOREM 4: 18-Decimal Clean Dust Truncation T_clean(R, 18)
// Theory Spec §3.2 eq (217-220)
//
// T_clean(R, 18) = floor(R / 10^12) * 10^12
// Guarantees R_expected mod 10^12 == 0 on 18-decimal tokens
// ============================================================================

#[test]
fn test_theorem_4_18_decimal_dust_truncation() {
    let invoice_usd = UsdMicros(33 * UsdMicros::SCALE); // $33.00
    // Arbitrary price creating infinite fractional digits: $2,789.123456
    let eth_price = UsdMicros(2_789_123_456);

    let quote_18 = invoice_usd
        .to_locked_quote_raw(eth_price, 18)
        .expect("valid quote");

    // Theorem: Lowest 12 digits must be exactly 0
    let dust_modulus = U256::from(1_000_000_000_000_u64); // 10^12
    let rem = quote_18.raw() % dust_modulus;
    assert_eq!(
        rem,
        U256::ZERO,
        "18-decimal quote contains unmasked dust digits: {}",
        quote_18.raw()
    );

    // Human-readable string representation must be at most 6 decimal places
    let display_str = quote_18.to_clean_display_string().expect("display string");
    if let Some((_whole, frac)) = display_str.split_once('.') {
        assert!(
            frac.len() <= 6,
            "Clean display string has more than 6 decimal places: {display_str}"
        );
    }
}

// ============================================================================
// THEOREM 5: Tron 1-Sun Dust Keeper Storage Warmth Savings
// Theory Spec §2.2 eq (148-154)
//
// V_sweep = B_current - 1 raw unit if KeepOneUnitDust == true and B_current > 1
// Retains 1 raw unit to keep SSTORE warm (saves 65,000 Energy = ~50% gas)
// ============================================================================

#[test]
fn test_theorem_5_tron_1_sun_dust_keeper() {
    let asset_tron_usdt = PhysicalAssetId {
        chain_id: ChainId::TronMainnet,
        logical_asset: LogicalAsset::Usdt,
        token_contract: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".to_string(),
        decimals: 6,
        keep_one_unit_dust: true,
        target_confirmations: 19,
    };

    let calculate_sweep_amount = |balance: U256, asset: &PhysicalAssetId| -> U256 {
        if asset.keep_one_unit_dust && balance > U256::from(1_u64) {
            balance - U256::from(1_u64)
        } else {
            balance
        }
    };

    // Case 1: 50.00 USDT deposited (50_000_000 raw units)
    let balance = U256::from(50_000_000_u64);
    let sweep = calculate_sweep_amount(balance, &asset_tron_usdt);
    // Sweeps 49_999_999, leaves 1 raw unit (1 Sun) in customer proxy
    assert_eq!(sweep, U256::from(49_999_999_u64));
    let remaining = balance - sweep;
    assert_eq!(remaining, U256::from(1_u64));

    // Case 2: On non-dust asset (e.g. Ethereum), sweeps 100% of balance
    let asset_eth_usdt = PhysicalAssetId {
        chain_id: ChainId::EthereumMainnet,
        logical_asset: LogicalAsset::Usdt,
        token_contract: "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
        decimals: 6,
        keep_one_unit_dust: false,
        target_confirmations: 12,
    };
    let eth_sweep = calculate_sweep_amount(balance, &asset_eth_usdt);
    assert_eq!(eth_sweep, balance);
}

// ============================================================================
// THEOREM 6: Exact Integer FIFO Cost-Basis Prefix Depletion Calculus
// Theory Spec §7.2 eq (1764-1771)
//
// delta_k = max(0, min(q_k, D - S_{k-1}))
// CostBasis_mu(D) = sum floor((delta_k * P_acq_k) / 10^d)
// Proceeds_mu(D) = floor((D * P_exec) / 10^d)
// RealizedPnL_mu(D) = Proceeds - CostBasis - Fee
// ============================================================================

#[derive(Debug, Clone)]
struct FifoLot {
    remaining_raw: U256,
    acq_price_usd_micros: u128,
}

#[derive(Debug, PartialEq, Eq)]
struct FifoDisposalOutcome {
    consumed_lots: Vec<(usize, U256)>, // (lot_index, consumed_amount)
    total_cost_basis_micros: u128,
    gross_proceeds_micros: u128,
    net_realized_pnl_micros: i128,
}

fn execute_fifo_disposal(
    lots: &mut [FifoLot],
    disposal_amount_raw: U256,
    exec_price_usd_micros: u128,
    fee_usd_micros: u128,
    decimals: u8,
) -> Result<FifoDisposalOutcome, SovereignError> {
    let scale = U256::from(10_u64)
        .checked_pow(U256::from(decimals))
        .ok_or(SovereignError::Overflow { context: "fifo::scale" })?;

    let mut prefix_sum = U256::ZERO;
    let mut consumed_lots = Vec::new();
    let mut total_cost_basis: u128 = 0;

    for (idx, lot) in lots.iter_mut().enumerate() {
        if prefix_sum >= disposal_amount_raw {
            break;
        }

        let s_k_minus_1 = prefix_sum;
        prefix_sum = prefix_sum.checked_add(lot.remaining_raw).unwrap();

        let diff = disposal_amount_raw.saturating_sub(s_k_minus_1);
        let delta_k = lot.remaining_raw.min(diff);

        if !delta_k.is_zero() {
            lot.remaining_raw = lot.remaining_raw - delta_k;
            consumed_lots.push((idx, delta_k));

            // Cost basis for this slice: floor((delta_k * P_acq) / 10^d)
            let lot_cost_u256 = delta_k
                .checked_mul(U256::from(lot.acq_price_usd_micros))
                .unwrap()
                .checked_div(scale)
                .unwrap();
            let lot_cost: u128 = u128::try_from(lot_cost_u256).unwrap();
            total_cost_basis = total_cost_basis.checked_add(lot_cost).unwrap();
        }
    }

    if prefix_sum < disposal_amount_raw {
        return Err(SovereignError::General("Insufficient inventory for disposal".to_string()));
    }

    let proceeds_u256 = disposal_amount_raw
        .checked_mul(U256::from(exec_price_usd_micros))
        .unwrap()
        .checked_div(scale)
        .unwrap();
    let gross_proceeds: u128 = u128::try_from(proceeds_u256).unwrap();

    let net_realized_pnl: i128 = (gross_proceeds as i128)
        - (total_cost_basis as i128)
        - (fee_usd_micros as i128);

    Ok(FifoDisposalOutcome {
        consumed_lots,
        total_cost_basis_micros: total_cost_basis,
        gross_proceeds_micros: gross_proceeds,
        net_realized_pnl_micros: net_realized_pnl,
    })
}

#[test]
fn test_theorem_6_exact_fifo_depletion_calculus() {
    // Inventory of 3 BTC lots acquired at different times & prices:
    // Lot 0: 1.0 BTC (100_000_000 sat) @ $50,000.00
    // Lot 1: 2.0 BTC (200_000_000 sat) @ $60,000.00
    // Lot 2: 1.5 BTC (150_000_000 sat) @ $70,000.00
    let mut inventory = vec![
        FifoLot {
            remaining_raw: U256::from(100_000_000_u64),
            acq_price_usd_micros: 50_000 * UsdMicros::SCALE,
        },
        FifoLot {
            remaining_raw: U256::from(200_000_000_u64),
            acq_price_usd_micros: 60_000 * UsdMicros::SCALE,
        },
        FifoLot {
            remaining_raw: U256::from(150_000_000_u64),
            acq_price_usd_micros: 70_000 * UsdMicros::SCALE,
        },
    ];

    // Outbound disposal: Sell 2.5 BTC (250_000_000 sat) @ $80,000.00 execution price with $15.00 network fee
    // FIFO consumption:
    // Lot 0: consumes all 1.0 BTC (cost basis = 1.0 * 50k = $50,000.00)
    // Lot 1: consumes 1.5 BTC (cost basis = 1.5 * 60k = $90,000.00), leaving 0.5 BTC
    // Lot 2: untouched (1.5 BTC remaining)
    // Total cost basis = $140,000.00 = 140_000_000_000 micros
    // Gross proceeds = 2.5 * 80k = $200,000.00 = 200_000_000_000 micros
    // Net Realized PnL = 200,000 - 140,000 - 15 = +$59,985.00 = +59_985_000_000 micros
    let disposal_amt = U256::from(250_000_000_u64);
    let exec_price = 80_000 * UsdMicros::SCALE;
    let fee = 15 * UsdMicros::SCALE;

    let outcome = execute_fifo_disposal(&mut inventory, disposal_amt, exec_price, fee, 8)
        .expect("FIFO disposal succeeds");

    assert_eq!(outcome.consumed_lots.len(), 2);
    assert_eq!(outcome.consumed_lots[0], (0, U256::from(100_000_000_u64)));
    assert_eq!(outcome.consumed_lots[1], (1, U256::from(150_000_000_u64)));

    assert_eq!(outcome.total_cost_basis_micros, 140_000 * UsdMicros::SCALE);
    assert_eq!(outcome.gross_proceeds_micros, 200_000 * UsdMicros::SCALE);
    assert_eq!(outcome.net_realized_pnl_micros, 59_985 * (UsdMicros::SCALE as i128));

    // Verify remaining inventory post-disposal:
    assert_eq!(inventory[0].remaining_raw, U256::ZERO);
    assert_eq!(inventory[1].remaining_raw, U256::from(50_000_000_u64)); // 0.5 BTC
    assert_eq!(inventory[2].remaining_raw, U256::from(150_000_000_u64)); // 1.5 BTC
}

// ============================================================================
// THEOREM 7: Proportional Hot-Wallet Overflow Split Zero-Dust Invariant
// Theory Spec §7.3 eq (1779-1781)
//
// Q_Cold = floor((B * alpha_cold) / 10,000)
// Q_Market = B - Q_Cold
// Invariant: Q_Cold + Q_Market == B (Exact conservation of mass, 0 dust loss)
// ============================================================================

#[test]
fn test_theorem_7_proportional_hot_wallet_zero_dust_split() {
    let split_hot_wallet = |balance: U256, alpha_cold_bps: u16| -> (U256, U256) {
        let q_cold = balance
            .checked_mul(U256::from(alpha_cold_bps))
            .unwrap()
            .checked_div(U256::from(10_000_u64))
            .unwrap();
        let q_market = balance - q_cold;
        (q_cold, q_market)
    };

    // Test with prime numbers and odd balances to stress integer division truncation
    let balances = vec![
        U256::from(10_000_003_u64),
        U256::from(999_999_999_u64),
        U256::from(1_234_567_891_u64),
    ];
    let policies = vec![7000_u16, 8500_u16, 3333_u16, 5000_u16];

    for b in balances {
        for alpha in &policies {
            let (q_cold, q_market) = split_hot_wallet(b, *alpha);
            assert_eq!(
                q_cold + q_market,
                b,
                "Dust leakage detected: Q_cold ({q_cold}) + Q_market ({q_market}) != Balance ({b})"
            );
        }
    }
}

// ============================================================================
// THEOREM 8: Erlang-B Guest Address Pool Sizing Normal Approximation
// Theory Spec §4.3 eq (285-294)
//
// M* >= ceil(A + 6.109 * sqrt(A))
// Guarantees B(M, A) < 10^-9 (< 1 pool exhaustion per billion checkouts)
// ============================================================================

#[test]
fn test_theorem_8_erlang_b_pool_sizing_bound() {
    let compute_safe_pool_size = |lambda_rate: f64, tau_lease_sec: f64, tau_cool_sec: f64| -> u64 {
        let holding_time = tau_lease_sec + tau_cool_sec;
        let offered_load_a = lambda_rate * holding_time;
        let margin = 6.109 * offered_load_a.sqrt();
        (offered_load_a + margin).ceil() as u64
    };

    // Example from Theory spec:
    // lambda = 2 checkouts/sec, lease = 900s (15 min), cooldown = 14400s (4 hours)
    // A = 2 * 15300 = 30600 Erlangs
    // Sqrt(30600) = 174.928
    // Margin = 6.109 * 174.928 = 1068.638
    // M* = 30600 + 1069 = 31669 addresses
    let pool_size = compute_safe_pool_size(2.0, 900.0, 14400.0);
    assert_eq!(pool_size, 31669);
}

// ============================================================================
// THEOREM 9: 5-Gate Formal State Transition Equation
// Theory Spec §5.2 eq (334-341)
//
// Evaluates all 6 disjoint outcomes of Master Typestate Transition Equation
// ============================================================================

#[derive(Debug, PartialEq, Eq)]
enum MasterTypestateOutcome {
    RevertedOnChain,
    SpoofedTokenContract,
    QuoteExpired,
    DetectedWaitingConfirmations,
    PartialUnderpaid { shortfall_raw: U256 },
    VerifiedCompleteExact,
    VerifiedCompleteOverpaid { surplus_raw: U256 },
}

fn evaluate_5_gates(
    execution_succeeded: bool,
    token_contract_matches: bool,
    block_timestamp_unix: u64,
    invoice_expires_at_unix: u64,
    parent_hash_continuous: bool,
    confirmations: u32,
    target_confirmations: u32,
    total_received_raw: U256,
    expected_amount_raw: U256,
    tolerance_bps: u16,
) -> MasterTypestateOutcome {
    // Gate 1: Execution Success
    if !execution_succeeded {
        return MasterTypestateOutcome::RevertedOnChain;
    }

    // Gate 2: Contract Whitelist
    if !token_contract_matches {
        return MasterTypestateOutcome::SpoofedTokenContract;
    }

    // Gate 4: Temporal Window
    if block_timestamp_unix > invoice_expires_at_unix {
        return MasterTypestateOutcome::QuoteExpired;
    }

    // Gate 5: Continuity & Finality
    let is_final = parent_hash_continuous && (confirmations >= target_confirmations);
    if !is_final {
        return MasterTypestateOutcome::DetectedWaitingConfirmations;
    }

    // Gate 3: Slippage & Overpayment Partition
    let min_tolerance_multiplier = 10_000_u64.saturating_sub(u64::from(tolerance_bps));
    let r_min = expected_amount_raw
        .checked_mul(U256::from(min_tolerance_multiplier))
        .unwrap()
        .checked_div(U256::from(10_000_u64))
        .unwrap();

    let r_over = expected_amount_raw
        .checked_mul(U256::from(10_200_u64)) // 102%
        .unwrap()
        .checked_div(U256::from(10_000_u64))
        .unwrap();

    if total_received_raw < r_min {
        let shortfall = expected_amount_raw - total_received_raw;
        MasterTypestateOutcome::PartialUnderpaid { shortfall_raw: shortfall }
    } else if total_received_raw > r_over {
        let surplus = total_received_raw - expected_amount_raw;
        MasterTypestateOutcome::VerifiedCompleteOverpaid { surplus_raw: surplus }
    } else {
        MasterTypestateOutcome::VerifiedCompleteExact
    }
}

#[test]
fn test_theorem_9_five_gate_typestate_transitions() {
    let expected = U256::from(100_000_000_u64); // 100 USDT
    let tolerance_bps = 50_u16; // 0.5% tolerance (r_min = 99.5 USDT)

    // 1. Gate 1 failure: Reverted transaction
    let o1 = evaluate_5_gates(false, true, 100, 200, true, 20, 12, expected, expected, tolerance_bps);
    assert_eq!(o1, MasterTypestateOutcome::RevertedOnChain);

    // 2. Gate 2 failure: Spoofed token contract
    let o2 = evaluate_5_gates(true, false, 100, 200, true, 20, 12, expected, expected, tolerance_bps);
    assert_eq!(o2, MasterTypestateOutcome::SpoofedTokenContract);

    // 3. Gate 4 failure: Quote expired
    let o3 = evaluate_5_gates(true, true, 250, 200, true, 20, 12, expected, expected, tolerance_bps);
    assert_eq!(o3, MasterTypestateOutcome::QuoteExpired);

    // 4. Gate 5 pending: Only 3 confirmations out of 12 required -> Detected
    let o4 = evaluate_5_gates(true, true, 100, 200, true, 3, 12, expected, expected, tolerance_bps);
    assert_eq!(o4, MasterTypestateOutcome::DetectedWaitingConfirmations);

    // 5. Gate 3 underpaid: Received 80 USDT (< 99.5 r_min) -> Partial
    let o5 = evaluate_5_gates(
        true, true, 100, 200, true, 12, 12,
        U256::from(80_000_000_u64), expected, tolerance_bps,
    );
    assert_eq!(o5, MasterTypestateOutcome::PartialUnderpaid {
        shortfall_raw: U256::from(20_000_000_u64),
    });

    // 6. Gate 3 exact: Received 99.8 USDT (within 99.5 - 102.0) -> VerifiedCompleteExact
    let o6 = evaluate_5_gates(
        true, true, 100, 200, true, 12, 12,
        U256::from(99_800_000_u64), expected, tolerance_bps,
    );
    assert_eq!(o6, MasterTypestateOutcome::VerifiedCompleteExact);

    // 7. Gate 3 overpaid: Received 105 USDT (> 102.0 r_over) -> VerifiedCompleteOverpaid
    let o7 = evaluate_5_gates(
        true, true, 100, 200, true, 12, 12,
        U256::from(105_000_000_u64), expected, tolerance_bps,
    );
    assert_eq!(o7, MasterTypestateOutcome::VerifiedCompleteOverpaid {
        surplus_raw: U256::from(5_000_000_u64),
    });
}

// ============================================================================
// THEOREM 10: Retention Priority Score Quota Isolation Bound
// Theory Spec §4.2.2 eq (262-266)
//
// Phi(x, t) = omega(p_x) * 10^9 + floor(((f_hit + 1) * TTL_rem) / S_bytes)
// Quota Isolation Theorem: Critical tiers (P0, P1, P2) always outscore P3 and P4
// ============================================================================

#[test]
fn test_theorem_10_priority_score_quota_isolation() {
    let compute_phi = |tier: CachePriorityTier, hit_count: u64, ttl_rem_ms: u64, size_bytes: u64| -> u128 {
        let base_weight = tier.base_weight() as u128;
        let scale_factor = 1_000_000_000_u128;
        let term1 = base_weight.saturating_mul(scale_factor);

        let term2 = (hit_count as u128 + 1)
            .saturating_mul(ttl_rem_ms as u128)
            .checked_div(size_bytes.max(1) as u128)
            .unwrap_or(0);

        term1.saturating_add(term2)
    };

    // Even under extreme spam where an attacker creates 1,000,000 hits on a P4 idempotency key
    // with max TTL:
    let phi_p4_spammed = compute_phi(CachePriorityTier::P4TelemetryIdempotency, 1_000_000, 86_400_000, 64);
    // Versus a freshly inserted, unhit P2 deposit pool lease:
    let phi_p2_fresh = compute_phi(CachePriorityTier::P2PoolLeaseCooldown, 0, 14_400_000, 64);
    // Versus a freshly inserted P1 active invoice:
    let phi_p1_fresh = compute_phi(CachePriorityTier::P1ActivePaymentWatch, 0, 900_000, 64);
    // Versus P0 consensus contract whitelist:
    let phi_p0 = compute_phi(CachePriorityTier::P0CriticalConsensus, 0, 0, 64);

    assert!(phi_p0 > phi_p1_fresh, "P0 must strictly dominate P1");
    assert!(phi_p1_fresh > phi_p2_fresh, "P1 must strictly dominate P2");
    assert!(phi_p2_fresh > phi_p4_spammed, "P2 must strictly dominate P4 even under 1M hit spam");
}
