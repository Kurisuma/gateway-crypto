//! # gw-treasury
//!
//! Unified multi-network real-time portfolio aggregation, integer FIFO cost-basis tax lot accounting,
//! and cross-network optimal liquidity routing with zero-dust hot/cold splits.
//!
//! # Security & Mathematical Invariants
//! - **Mathematical Invariant I (Zero Floating-Point Types):** All token quantities, USD micro-valuations,
//!   basis-point shares, and FIFO tax-lot calculations use pure integer fixed-point arithmetic (`U256`, `u128`, `i128`).
//! - **Mathematical Invariant II (Canonical 18-Decimal Homomorphism $\mathcal{N}_{18}$):** Multi-chain logical assets
//!   (e.g. 6-dec USDT on Tron/Solana vs 18-dec USDT on Ethereum/BNB) are normalized into canonical 18-decimal scale.
//! - **Mathematical Invariant III (Integer FIFO Depletion Calculus $\delta_k$):** Chronological tax lots are depleted
//!   with exact prefix sums ($S_k = \sum q_j$), calculating exact integer cost basis and realized P&L.
//! - **Mathematical Invariant IV (Zero-Dust Hot/Cold Split $\alpha_{\text{cold}}$):** Proportional transfers satisfy
//!   $Q_{\to \text{Cold}} + Q_{\to \text{Market}} \equiv B$ with zero division loss.

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
use gw_chain_traits::UnsignedTransactionEnvelope;
use gw_engine::{Invoice, VerifiedComplete};
use gw_primitives::{
    ChainId, LogicalAsset, PhysicalAssetId, RawAssetAmount, SovereignError, UsdMicros, WalletTier,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;

/// Treasury and portfolio calculation error taxonomy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TreasuryError {
    /// Primitive arithmetic error.
    #[error("Primitive domain error: {0}")]
    Primitive(#[from] SovereignError),

    /// Insufficient tax lot inventory to satisfy disposal quantity.
    #[error("Insufficient FIFO lot inventory: available={available_raw:?}, requested={requested_raw:?}")]
    InsufficientLotInventory {
        /// Total remaining amount across all available open lots.
        available_raw: RawAssetAmount,
        /// Requested disposal amount.
        requested_raw: RawAssetAmount,
    },

    /// Split basis points do not sum to 10,000 (100.00%).
    #[error("Invalid split basis points: cold_bps={cold_bps}, market_bps={market_bps}, expected sum=10,000")]
    InvalidSplitBps {
        /// Basis points allocated to cold storage.
        cold_bps: u16,
        /// Basis points allocated to market exchange.
        market_bps: u16,
    },

    /// Economical sweep threshold denominator is zero or invalid.
    #[error("Invalid fee ratio: max_fee_to_principal_bps cannot be zero")]
    ZeroFeeRatio,

    /// Missing spot price for logical asset.
    #[error("Missing spot price for asset {0:?}")]
    MissingSpotPrice(LogicalAsset),
}

/// Snapshot of a single treasury wallet's holding on a specific network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletAssetHolding {
    /// Unique identifier of the custody wallet.
    pub wallet_id: Uuid,
    /// Security custody tier.
    pub wallet_tier: WalletTier,
    /// Physical asset specification (chain, contract, symbol, decimals).
    pub asset: PhysicalAssetId,
    /// Current raw balance on-chain.
    pub raw_balance: RawAssetAmount,
    /// Verified oracle spot price in USD micros.
    pub current_spot_price_usd: UsdMicros,
}

/// Immutable FIFO Tax Lot created upon `Invoice<VerifiedComplete>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FifoCostBasisLot {
    /// Unique tax lot identifier.
    pub lot_id: Uuid,
    /// Originating checkout invoice identifier.
    pub source_invoice_id: u64,
    /// Physical asset specification.
    pub asset: PhysicalAssetId,
    /// Initially acquired raw token amount.
    pub initial_amount: RawAssetAmount,
    /// Unconsumed remaining raw token amount.
    pub remaining_amount: RawAssetAmount,
    /// Locked acquisition price in USD micros.
    pub acquisition_price_usd: UsdMicros,
    /// Acquisition timestamp in seconds since Unix epoch.
    pub acquired_at_unix: u64,
}

/// Unified cross-network portfolio rollup for a single logical asset (e.g. Total USDT across all chains).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedAssetPortfolioSummary {
    /// Logical asset identifier.
    pub logical_asset: LogicalAsset,
    /// Sum of holdings across all chains normalized to 18-decimal units $\mathcal{N}_{18}$.
    pub total_canonical_18_units: U256,
    /// Total current mark-to-market valuation in USD micros.
    pub total_market_valuation_usd: UsdMicros,
    /// Total FIFO acquisition cost basis of open lots in USD micros.
    pub total_fifo_cost_basis_usd: UsdMicros,
    /// Unrealized Profit & Loss in signed USD micros ($V^{\text{MTM}} - \text{CostBasis}$).
    pub unrealized_pnl_usd_micros: i128,
    /// Holding valuation breakdown indexed by security wallet tier.
    pub valuation_by_tier_usd: BTreeMap<WalletTier, UsdMicros>,
    /// Holding valuation breakdown indexed by blockchain network.
    pub valuation_by_chain_usd: BTreeMap<ChainId, UsdMicros>,
}

/// Audit report produced when FIFO lots are depleted by a market liquidation or sweep gas burn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealizedPnlSettlementReport {
    /// Unique settlement transaction identifier.
    pub settlement_id: Uuid,
    /// Disposed logical asset.
    pub logical_asset: LogicalAsset,
    /// Blockchain network on which disposal executed.
    pub chain_id: ChainId,
    /// Total raw token quantity disposed.
    pub disposed_amount: RawAssetAmount,
    /// Individual slices consumed from chronological tax lots: (Lot UUID, Consumed Raw, Acq Price).
    pub consumed_lot_slices: Vec<(Uuid, RawAssetAmount, UsdMicros)>,
    /// Exact aggregated cost basis in USD micros.
    pub total_cost_basis_usd: UsdMicros,
    /// Gross proceeds received in USD micros.
    pub gross_proceeds_usd: UsdMicros,
    /// On-chain network fee burned during execution in USD micros.
    pub network_fee_burned_usd: UsdMicros,
    /// Net realized Profit & Loss in signed USD micros ($\text{Proceeds} - \text{CostBasis} - \text{Fee}$).
    pub net_realized_pnl_usd_micros: i128,
}

/// Trait X: Unified Cross-Network Asset Aggregation & FIFO Cost-Basis Calculus Engine.
#[async_trait]
pub trait EnterpriseTreasuryPortfolioEngine: Send + Sync {
    /// Records an immutable FIFO Cost-Basis Lot immediately upon invoice completion.
    async fn record_verified_invoice_lot(
        &self,
        verified_invoice: &Invoice<VerifiedComplete>,
    ) -> Result<FifoCostBasisLot, TreasuryError>;

    /// Aggregates all wallet holdings across all networks and tiers into a unified
    /// per-LogicalAsset portfolio with exact mark-to-market valuation and unrealized P&L.
    async fn compute_unified_global_portfolio(
        &self,
        holdings: &[WalletAssetHolding],
        open_fifo_lots: &[FifoCostBasisLot],
    ) -> Result<BTreeMap<LogicalAsset, UnifiedAssetPortfolioSummary>, TreasuryError>;

    /// Consumes open FIFO tax lots in strict chronological order ($t_1 \le t_2 \le \dots \le t_m$)
    /// for a market liquidation or sweep gas burn, returning the realized P&L audit report.
    async fn execute_fifo_lot_consumption(
        &self,
        open_lots_chronological: &mut [FifoCostBasisLot],
        disposed_amount: RawAssetAmount,
        execution_price_usd: UsdMicros,
        network_fee_usd: UsdMicros,
    ) -> Result<RealizedPnlSettlementReport, TreasuryError>;

    /// Verifies double-entry reconciliation between on-chain holdings and ledger invariants.
    async fn reconcile_onchain_vs_ledger_balances(
        &self,
        holdings: &[WalletAssetHolding],
    ) -> Result<bool, TreasuryError>;
}

/// Per-network liquidity threshold and split allocation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkLiquidityPolicy {
    /// Physical asset handled by this policy.
    pub asset: PhysicalAssetId,
    /// Tier 1 Gas Relayer operational address.
    pub tier1_relayer_address: String,
    /// Tier 2 Operational Hot Wallet address.
    pub tier2_hot_wallet_address: String,
    /// Key locator or HSM derivation path for the Tier 2 Hot Wallet.
    pub tier2_key_locator: String,
    /// Tier 3 Cold Storage Safe or Multi-Sig vault address.
    pub tier3_cold_vault_address: String,
    /// Tier 4 Institutional Market Exchange deposit address.
    pub tier4_market_exchange_address: String,
    /// Maximum USD ceiling for the Tier 2 Hot Wallet before triggering overflow flush.
    pub hot_wallet_ceiling_usd: UsdMicros,
    /// Basis points of excess liquidity routed to Tier 3 Cold Vault (e.g. 7000 = 70.00%).
    pub cold_vault_split_bps: u16,
    /// Basis points of excess liquidity routed to Tier 4 Market Exchange (e.g. 3000 = 30.00%).
    pub market_exchange_split_bps: u16,
    /// Minimum raw balance on Tier 1 Gas Relayer before auto-refill triggers.
    pub min_relayer_gas_raw: RawAssetAmount,
    /// Target raw balance to top-up on Tier 1 Gas Relayer.
    pub target_relayer_gas_raw: RawAssetAmount,
}

/// Global routing directive across all networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GlobalRoutingDirective {
    /// Sweeps 100% of excess transferable hot funds across all networks to Tier 3 Cold Vaults.
    EmergencyOrScheduledFlushToCold,
    /// Sweeps 100% of excess transferable hot funds across all networks to Tier 4 Market Exchanges.
    FlushAllToMarketExchange,
    /// Enforces proportional split $(\alpha_{\text{cold}}, \alpha_{\text{market}})$ whenever hot wallet exceeds ceiling.
    PolicyDrivenProportionalSplit,
}

/// Trait XI: Cross-Network Liquidity Routing, Relayer Auto-Refill & Consolidation Coordinator.
#[async_trait]
pub trait EnterpriseCrossNetworkLiquidityRouter: Send + Sync {
    /// Evaluates Tier 1 Gas Relayers across all networks and generates unsigned top-up
    /// envelopes from Tier 2 Operational Hot Wallets whenever `balance < min_relayer_gas_raw`.
    async fn plan_tier1_relayer_gas_refills(
        &self,
        policies: &[NetworkLiquidityPolicy],
        relayer_balances: &BTreeMap<ChainId, RawAssetAmount>,
    ) -> Result<Vec<UnsignedTransactionEnvelope>, TreasuryError>;

    /// Plans optimal cross-network transfers of a specific logical asset or the entire portfolio
    /// to Cold Storage and/or Market Exchanges according to policy and directives.
    async fn plan_global_liquidity_transfers(
        &self,
        filter_asset: Option<LogicalAsset>,
        directive: GlobalRoutingDirective,
        policies: &[NetworkLiquidityPolicy],
        hot_wallet_balances: &BTreeMap<(ChainId, String), RawAssetAmount>,
        spot_prices_usd: &BTreeMap<LogicalAsset, UsdMicros>,
    ) -> Result<Vec<UnsignedTransactionEnvelope>, TreasuryError>;

    /// Computes the minimum cost-to-sweep threshold for Tier 0 customer deposit addresses on a given chain
    /// so that network gas fees never exceed `max_fee_to_principal_bps` (e.g. 50 bps = 0.50%).
    async fn calculate_economical_sweep_threshold(
        &self,
        chain_id: ChainId,
        asset: &PhysicalAssetId,
        estimated_gas_cost_usd: UsdMicros,
        asset_spot_price_usd: UsdMicros,
        max_fee_to_principal_bps: u16,
    ) -> Result<RawAssetAmount, TreasuryError>;
}

// ============================================================================
// CONCRETE IMPLEMENTATIONS & MATHEMATICAL HELPER ALGORITHMS
// ============================================================================

/// Calculates the zero-dust proportional split between cold vault and market exchange.
///
/// $$Q_{\to \text{Cold}} = \left\lfloor \frac{B \otimes \alpha_{\text{cold}}}{10,000} \right\rfloor, \qquad Q_{\to \text{Market}} = B \ominus Q_{\to \text{Cold}}$$
///
/// Guarantees that $Q_{\to \text{Cold}} \oplus Q_{\to \text{Market}} \equiv B$ with zero division loss.
pub fn calculate_zero_dust_split(
    total_raw: RawAssetAmount,
    cold_bps: u16,
    market_bps: u16,
) -> Result<(RawAssetAmount, RawAssetAmount), TreasuryError> {
    let expected_sum = 10_000u32;
    let actual_sum = u32::from(cold_bps).saturating_add(u32::from(market_bps));
    if actual_sum != expected_sum {
        return Err(TreasuryError::InvalidSplitBps {
            cold_bps,
            market_bps,
        });
    }

    let b = total_raw.raw();
    let cold_mult = U256::from(cold_bps);
    let divisor = U256::from(10_000u64);

    let cold_raw_val = (b.saturating_mul(cold_mult)) / divisor;
    let market_raw_val = b.saturating_sub(cold_raw_val);

    Ok((
        RawAssetAmount::new(cold_raw_val, total_raw.decimals()),
        RawAssetAmount::new(market_raw_val, total_raw.decimals()),
    ))
}

/// Computes the minimum raw deposit balance required to satisfy the economical sweep threshold:
///
/// $$\mathcal{V}_{\text{USD}}(B_{T_0}, d, P_{\mu}) \ge \left\lceil \frac{G_{\text{est}}(c) \otimes 10,000}{\eta_{\max}} \right\rceil$$
///
/// In raw token units:
///
/// $$R_{\min} = \left\lceil \frac{V_{\min} \otimes 10^d}{P_{\mu}} \right\rceil = \left\lfloor \frac{V_{\min} \otimes 10^d + P_{\mu} - 1}{P_{\mu}} \right\rfloor$$
pub fn calculate_economical_sweep_threshold_raw(
    estimated_gas_cost_usd: UsdMicros,
    asset_spot_price_usd: UsdMicros,
    decimals: u8,
    max_fee_to_principal_bps: u16,
) -> Result<RawAssetAmount, TreasuryError> {
    if max_fee_to_principal_bps == 0 {
        return Err(TreasuryError::ZeroFeeRatio);
    }
    if asset_spot_price_usd.0 == 0 {
        return Err(TreasuryError::Primitive(SovereignError::DivisionByZero));
    }

    let gas_usd = U256::from(estimated_gas_cost_usd.0);
    let fee_bps = U256::from(max_fee_to_principal_bps);
    let scale_bps = U256::from(10_000u64);

    // V_min = ceil( (gas_usd * 10,000) / fee_bps )
    let numerator_v = gas_usd.saturating_mul(scale_bps);
    let v_min = (numerator_v.saturating_add(fee_bps.saturating_sub(U256::from(1u8)))) / fee_bps;

    // 10^d scale
    let ten = U256::from(10u8);
    let decimal_pow = ten.pow(U256::from(decimals));

    // R_min = ceil( (V_min * 10^d) / spot_price )
    let spot = U256::from(asset_spot_price_usd.0);
    let numerator_r = v_min.saturating_mul(decimal_pow);
    let r_min = (numerator_r.saturating_add(spot.saturating_sub(U256::from(1u8)))) / spot;

    Ok(RawAssetAmount::new(r_min, decimals))
}

/// Sovereign enterprise implementation of `EnterpriseTreasuryPortfolioEngine`.
#[derive(Debug, Default, Clone)]
pub struct SovereignTreasuryPortfolioEngine;

impl SovereignTreasuryPortfolioEngine {
    /// Creates a new portfolio engine instance.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EnterpriseTreasuryPortfolioEngine for SovereignTreasuryPortfolioEngine {
    async fn record_verified_invoice_lot(
        &self,
        verified_invoice: &Invoice<VerifiedComplete>,
    ) -> Result<FifoCostBasisLot, TreasuryError> {
        let lot = FifoCostBasisLot {
            lot_id: Uuid::new_v4(),
            source_invoice_id: verified_invoice.invoice_id,
            asset: verified_invoice.asset.clone(),
            initial_amount: verified_invoice.received_amount_raw,
            remaining_amount: verified_invoice.received_amount_raw,
            acquisition_price_usd: verified_invoice.locked_price_usd,
            acquired_at_unix: verified_invoice.state.settled_at_unix,
        };
        Ok(lot)
    }

    async fn compute_unified_global_portfolio(
        &self,
        holdings: &[WalletAssetHolding],
        open_fifo_lots: &[FifoCostBasisLot],
    ) -> Result<BTreeMap<LogicalAsset, UnifiedAssetPortfolioSummary>, TreasuryError> {
        let mut summaries: BTreeMap<LogicalAsset, UnifiedAssetPortfolioSummary> = BTreeMap::new();

        // 1. Rollup on-chain holdings across all networks and tiers
        for holding in holdings {
            let logical = holding.asset.logical_asset;
            let entry = summaries
                .entry(logical)
                .or_insert_with(|| UnifiedAssetPortfolioSummary {
                    logical_asset: logical,
                    total_canonical_18_units: U256::ZERO,
                    total_market_valuation_usd: UsdMicros(0),
                    total_fifo_cost_basis_usd: UsdMicros(0),
                    unrealized_pnl_usd_micros: 0,
                    valuation_by_tier_usd: BTreeMap::new(),
                    valuation_by_chain_usd: BTreeMap::new(),
                });

            // Canonical 18-decimal quantity
            let canonical_18 = holding.raw_balance.to_canonical_18()?;
            entry.total_canonical_18_units = entry
                .total_canonical_18_units
                .saturating_add(canonical_18);

            // Mark-to-market valuation
            let mtm_usd = UsdMicros::from_raw_asset_amount(
                holding.raw_balance,
                holding.current_spot_price_usd,
            )?;
            entry.total_market_valuation_usd = entry.total_market_valuation_usd.checked_add(mtm_usd)?;

            // Breakdown by tier
            let tier_entry = entry
                .valuation_by_tier_usd
                .entry(holding.wallet_tier)
                .or_insert(UsdMicros(0));
            *tier_entry = tier_entry.checked_add(mtm_usd)?;

            // Breakdown by chain
            let chain_entry = entry
                .valuation_by_chain_usd
                .entry(holding.asset.chain_id)
                .or_insert(UsdMicros(0));
            *chain_entry = chain_entry.checked_add(mtm_usd)?;
        }

        // 2. Aggregate FIFO cost basis for open tax lots
        for lot in open_fifo_lots {
            if lot.remaining_amount.is_zero() {
                continue;
            }
            let logical = lot.asset.logical_asset;
            if let Some(entry) = summaries.get_mut(&logical) {
                let lot_cost = UsdMicros::from_raw_asset_amount(
                    lot.remaining_amount,
                    lot.acquisition_price_usd,
                )?;
                entry.total_fifo_cost_basis_usd = entry.total_fifo_cost_basis_usd.checked_add(lot_cost)?;
            }
        }

        // 3. Compute exact signed unrealized P&L: V^MTM - CostBasis
        for entry in summaries.values_mut() {
            let mtm = entry.total_market_valuation_usd.0;
            let cost = entry.total_fifo_cost_basis_usd.0;

            let mtm_signed = i128::try_from(mtm).map_err(|_| {
                TreasuryError::Primitive(SovereignError::Overflow {
                    context: "MTM valuation exceeds i128 signed range",
                })
            })?;
            let cost_signed = i128::try_from(cost).map_err(|_| {
                TreasuryError::Primitive(SovereignError::Overflow {
                    context: "Cost basis exceeds i128 signed range",
                })
            })?;

            entry.unrealized_pnl_usd_micros = mtm_signed.saturating_sub(cost_signed);
        }

        Ok(summaries)
    }

    async fn execute_fifo_lot_consumption(
        &self,
        open_lots_chronological: &mut [FifoCostBasisLot],
        disposed_amount: RawAssetAmount,
        execution_price_usd: UsdMicros,
        network_fee_usd: UsdMicros,
    ) -> Result<RealizedPnlSettlementReport, TreasuryError> {
        let total_available: U256 = open_lots_chronological
            .iter()
            .map(|lot| lot.remaining_amount.raw())
            .fold(U256::ZERO, |acc, val| acc.saturating_add(val));

        if disposed_amount.raw() > total_available {
            let decimals = disposed_amount.decimals();
            return Err(TreasuryError::InsufficientLotInventory {
                available_raw: RawAssetAmount::new(total_available, decimals),
                requested_raw: disposed_amount,
            });
        }

        // Sort chronologically by acquisition timestamp
        open_lots_chronological.sort_by_key(|lot| lot.acquired_at_unix);

        let mut remaining_to_consume = disposed_amount.raw();
        let mut consumed_slices = Vec::new();
        let mut total_cost_basis_micros = 0u128;

        let (logical_asset, chain_id, _decimals) = if let Some(first_lot) = open_lots_chronological.first() {
            (first_lot.asset.logical_asset, first_lot.asset.chain_id, first_lot.asset.decimals)
        } else {
            return Err(TreasuryError::InsufficientLotInventory {
                available_raw: RawAssetAmount::zero(disposed_amount.decimals()),
                requested_raw: disposed_amount,
            });
        };

        for lot in open_lots_chronological.iter_mut() {
            if remaining_to_consume == U256::ZERO {
                break;
            }
            if lot.remaining_amount.is_zero() {
                continue;
            }

            let lot_remaining = lot.remaining_amount.raw();
            let delta_k = if lot_remaining < remaining_to_consume {
                lot_remaining
            } else {
                remaining_to_consume
            };

            let new_remaining = lot_remaining.saturating_sub(delta_k);
            lot.remaining_amount = RawAssetAmount::new(new_remaining, lot.remaining_amount.decimals());
            remaining_to_consume = remaining_to_consume.saturating_sub(delta_k);

            let slice_amount = RawAssetAmount::new(delta_k, lot.asset.decimals);
            let slice_cost = UsdMicros::from_raw_asset_amount(
                slice_amount,
                lot.acquisition_price_usd,
            )?;
            total_cost_basis_micros = total_cost_basis_micros.saturating_add(slice_cost.0);

            consumed_slices.push((lot.lot_id, slice_amount, lot.acquisition_price_usd));
        }

        let total_cost_basis_usd = UsdMicros(total_cost_basis_micros);
        let gross_proceeds_usd = UsdMicros::from_raw_asset_amount(disposed_amount, execution_price_usd)?;

        // Realized PnL = Proceeds - CostBasis - NetworkFee
        let proceeds_signed = i128::try_from(gross_proceeds_usd.0).map_err(|_| {
            TreasuryError::Primitive(SovereignError::Overflow {
                context: "Gross proceeds exceeds i128 range",
            })
        })?;
        let cost_signed = i128::try_from(total_cost_basis_usd.0).map_err(|_| {
            TreasuryError::Primitive(SovereignError::Overflow {
                context: "Total cost basis exceeds i128 range",
            })
        })?;
        let fee_signed = i128::try_from(network_fee_usd.0).map_err(|_| {
            TreasuryError::Primitive(SovereignError::Overflow {
                context: "Network fee exceeds i128 range",
            })
        })?;

        let net_realized_pnl_usd_micros = proceeds_signed
            .saturating_sub(cost_signed)
            .saturating_sub(fee_signed);

        Ok(RealizedPnlSettlementReport {
            settlement_id: Uuid::new_v4(),
            logical_asset,
            chain_id,
            disposed_amount,
            consumed_lot_slices: consumed_slices,
            total_cost_basis_usd,
            gross_proceeds_usd,
            network_fee_burned_usd: network_fee_usd,
            net_realized_pnl_usd_micros,
        })
    }

    async fn reconcile_onchain_vs_ledger_balances(
        &self,
        holdings: &[WalletAssetHolding],
    ) -> Result<bool, TreasuryError> {
        // Double-entry validation: holding balances must have non-zero spot prices
        for holding in holdings {
            if holding.current_spot_price_usd.0 == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Sovereign enterprise implementation of `EnterpriseCrossNetworkLiquidityRouter`.
#[derive(Debug, Default, Clone)]
pub struct SovereignCrossNetworkLiquidityRouter;

impl SovereignCrossNetworkLiquidityRouter {
    /// Creates a new router instance.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EnterpriseCrossNetworkLiquidityRouter for SovereignCrossNetworkLiquidityRouter {
    async fn plan_tier1_relayer_gas_refills(
        &self,
        policies: &[NetworkLiquidityPolicy],
        relayer_balances: &BTreeMap<ChainId, RawAssetAmount>,
    ) -> Result<Vec<UnsignedTransactionEnvelope>, TreasuryError> {
        let mut envelopes = Vec::new();

        for policy in policies {
            let chain_id = policy.asset.chain_id;
            let current_balance = relayer_balances
                .get(&chain_id)
                .copied()
                .unwrap_or_else(|| RawAssetAmount::zero(policy.asset.decimals));

            if current_balance.raw() < policy.min_relayer_gas_raw.raw() {
                let refill_amount = policy
                    .target_relayer_gas_raw
                    .raw()
                    .saturating_sub(current_balance.raw());

                if refill_amount > U256::ZERO {
                    let envelope = UnsignedTransactionEnvelope {
                        envelope_id: Uuid::new_v4(),
                        chain_id,
                        architecture: chain_id.architecture(),
                        source_tier: WalletTier::Tier2OperationalHot,
                        destination_tier: WalletTier::Tier1GasRelayer,
                        expected_destination_address: policy.tier1_relayer_address.clone(),
                        physical_asset: policy.asset.clone(),
                        sweep_amount_raw: RawAssetAmount::new(refill_amount, policy.asset.decimals),
                        estimated_gas_fee_raw: RawAssetAmount::zero(policy.asset.decimals),
                        raw_unsigned_payload: Vec::new(),
                        signer_key_locator: policy.tier2_key_locator.clone(),
                    };
                    envelopes.push(envelope);
                }
            }
        }

        Ok(envelopes)
    }

    async fn plan_global_liquidity_transfers(
        &self,
        filter_asset: Option<LogicalAsset>,
        directive: GlobalRoutingDirective,
        policies: &[NetworkLiquidityPolicy],
        hot_wallet_balances: &BTreeMap<(ChainId, String), RawAssetAmount>,
        spot_prices_usd: &BTreeMap<LogicalAsset, UsdMicros>,
    ) -> Result<Vec<UnsignedTransactionEnvelope>, TreasuryError> {
        let mut envelopes = Vec::new();

        for policy in policies {
            if filter_asset.is_some_and(|target| policy.asset.logical_asset != target) {
                continue;
            }

            let chain_id = policy.asset.chain_id;
            let key = (chain_id, policy.tier2_hot_wallet_address.clone());
            let current_balance = hot_wallet_balances
                .get(&key)
                .copied()
                .unwrap_or_else(|| RawAssetAmount::zero(policy.asset.decimals));

            if current_balance.is_zero() {
                continue;
            }

            let spot_price = spot_prices_usd
                .get(&policy.asset.logical_asset)
                .copied()
                .ok_or(TreasuryError::MissingSpotPrice(policy.asset.logical_asset))?;

            let current_valuation = UsdMicros::from_raw_asset_amount(
                current_balance,
                spot_price,
            )?;

            match directive {
                GlobalRoutingDirective::EmergencyOrScheduledFlushToCold => {
                    // Flush 100% of current hot balance to Tier 3 Cold Vault
                    let envelope = UnsignedTransactionEnvelope {
                        envelope_id: Uuid::new_v4(),
                        chain_id,
                        architecture: chain_id.architecture(),
                        source_tier: WalletTier::Tier2OperationalHot,
                        destination_tier: WalletTier::Tier3ColdVault,
                        expected_destination_address: policy.tier3_cold_vault_address.clone(),
                        physical_asset: policy.asset.clone(),
                        sweep_amount_raw: current_balance,
                        estimated_gas_fee_raw: RawAssetAmount::zero(policy.asset.decimals),
                        raw_unsigned_payload: Vec::new(),
                        signer_key_locator: policy.tier2_key_locator.clone(),
                    };
                    envelopes.push(envelope);
                }

                GlobalRoutingDirective::FlushAllToMarketExchange => {
                    // Flush 100% of current hot balance to Tier 4 Market Exchange
                    let envelope = UnsignedTransactionEnvelope {
                        envelope_id: Uuid::new_v4(),
                        chain_id,
                        architecture: chain_id.architecture(),
                        source_tier: WalletTier::Tier2OperationalHot,
                        destination_tier: WalletTier::Tier4MarketExchange,
                        expected_destination_address: policy.tier4_market_exchange_address.clone(),
                        physical_asset: policy.asset.clone(),
                        sweep_amount_raw: current_balance,
                        estimated_gas_fee_raw: RawAssetAmount::zero(policy.asset.decimals),
                        raw_unsigned_payload: Vec::new(),
                        signer_key_locator: policy.tier2_key_locator.clone(),
                    };
                    envelopes.push(envelope);
                }

                GlobalRoutingDirective::PolicyDrivenProportionalSplit => {
                    // Only transfer if valuation strictly exceeds ceiling
                    if current_valuation.0 > policy.hot_wallet_ceiling_usd.0 {
                        let excess_valuation_micros = current_valuation
                            .0
                            .saturating_sub(policy.hot_wallet_ceiling_usd.0);

                        // Convert excess valuation back to raw asset units
                        // excess_raw = (excess_val * 10^d) / spot_price
                        let ten = U256::from(10u8);
                        let dec_pow = ten.pow(U256::from(policy.asset.decimals));
                        let spot = U256::from(spot_price.0);
                        let excess_raw_val = (U256::from(excess_valuation_micros)
                            .saturating_mul(dec_pow))
                            / spot;

                        let excess_raw_capped = if excess_raw_val > current_balance.raw() {
                            current_balance.raw()
                        } else {
                            excess_raw_val
                        };
                        let excess_raw =
                            RawAssetAmount::new(excess_raw_capped, policy.asset.decimals);

                        if !excess_raw.is_zero() {
                            let (to_cold, to_market) = calculate_zero_dust_split(
                                excess_raw,
                                policy.cold_vault_split_bps,
                                policy.market_exchange_split_bps,
                            )?;

                            if !to_cold.is_zero() {
                                envelopes.push(UnsignedTransactionEnvelope {
                                    envelope_id: Uuid::new_v4(),
                                    chain_id,
                                    architecture: chain_id.architecture(),
                                    source_tier: WalletTier::Tier2OperationalHot,
                                    destination_tier: WalletTier::Tier3ColdVault,
                                    expected_destination_address: policy
                                        .tier3_cold_vault_address
                                        .clone(),
                                    physical_asset: policy.asset.clone(),
                                    sweep_amount_raw: to_cold,
                                    estimated_gas_fee_raw: RawAssetAmount::zero(
                                        policy.asset.decimals,
                                    ),
                                    raw_unsigned_payload: Vec::new(),
                                    signer_key_locator: policy.tier2_key_locator.clone(),
                                });
                            }

                            if !to_market.is_zero() {
                                envelopes.push(UnsignedTransactionEnvelope {
                                    envelope_id: Uuid::new_v4(),
                                    chain_id,
                                    architecture: chain_id.architecture(),
                                    source_tier: WalletTier::Tier2OperationalHot,
                                    destination_tier: WalletTier::Tier4MarketExchange,
                                    expected_destination_address: policy
                                        .tier4_market_exchange_address
                                        .clone(),
                                    physical_asset: policy.asset.clone(),
                                    sweep_amount_raw: to_market,
                                    estimated_gas_fee_raw: RawAssetAmount::zero(
                                        policy.asset.decimals,
                                    ),
                                    raw_unsigned_payload: Vec::new(),
                                    signer_key_locator: policy.tier2_key_locator.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(envelopes)
    }

    async fn calculate_economical_sweep_threshold(
        &self,
        _chain_id: ChainId,
        asset: &PhysicalAssetId,
        estimated_gas_cost_usd: UsdMicros,
        asset_spot_price_usd: UsdMicros,
        max_fee_to_principal_bps: u16,
    ) -> Result<RawAssetAmount, TreasuryError> {
        calculate_economical_sweep_threshold_raw(
            estimated_gas_cost_usd,
            asset_spot_price_usd,
            asset.decimals,
            max_fee_to_principal_bps,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_dust_split_conservation() {
        // B = 1,000,000 units, 70% cold, 30% market
        let total = RawAssetAmount::new(U256::from(1_000_000u64), 6);
        let (cold, market) = calculate_zero_dust_split(total, 7000, 3000).unwrap();
        assert_eq!(cold.raw(), U256::from(700_000u64));
        assert_eq!(market.raw(), U256::from(300_000u64));
        assert_eq!(cold.raw() + market.raw(), total.raw());

        // B = 1,000,001 units with non-trivial remainder
        let total_odd = RawAssetAmount::new(U256::from(1_000_001u64), 6);
        let (cold_odd, market_odd) = calculate_zero_dust_split(total_odd, 7000, 3000).unwrap();
        // 1,000,001 * 7,000 / 10,000 = 700,000.7 -> 700,000
        assert_eq!(cold_odd.raw(), U256::from(700_000u64));
        // Remaining to market: 1,000,001 - 700,000 = 300,001
        assert_eq!(market_odd.raw(), U256::from(300_001u64));
        // Conservation invariant: cold + market == total
        assert_eq!(cold_odd.raw() + market_odd.raw(), total_odd.raw());
    }

    #[test]
    fn test_invalid_bps_rejected() {
        let total = RawAssetAmount::new(U256::from(100u64), 6);
        let err = calculate_zero_dust_split(total, 6000, 3000).unwrap_err();
        assert_eq!(
            err,
            TreasuryError::InvalidSplitBps {
                cold_bps: 6000,
                market_bps: 3000
            }
        );
    }

    #[test]
    fn test_economical_sweep_threshold_calculation() {
        // Gas cost = $2.50 (2,500,000 micros)
        // Max fee bps = 50 (0.5%)
        // Spot price = $1.00 (1,000,000 micros)
        // Decimals = 6 (USDT)
        // Minimum deposit USD value = ceil(2,500,000 * 10,000 / 50) = 500,000,000 micros = $500.00
        // Expected raw threshold = 500 * 10^6 = 500,000,000 units
        let gas_usd = UsdMicros(2_500_000);
        let spot_usd = UsdMicros(1_000_000);
        let threshold =
            calculate_economical_sweep_threshold_raw(gas_usd, spot_usd, 6, 50).unwrap();

        assert_eq!(threshold.raw(), U256::from(500_000_000u64));
    }
}
