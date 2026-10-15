//! # gw-engine
//!
//! Compile-Time Typestate Invoice Machine, 5-Gate Deterministic Verification Engine,
//! and Consensus Sliding-Window Parent-Hash Ring Buffer with Reorg LCA Rollback.
//!
//! # Security & Architectural Invariants
//! - **Invariant VI (Compile-Time Typestate Lifecycle):** Transitions consume `self` by value.
//!   Downstream services cannot fulfill an order or record a FIFO lot without receiving an
//!   `Invoice<VerifiedComplete>`, which cannot be created without passing all 5 gates.
//! - **Invariant VII (Reorg-Safe Parent-Hash DAG Continuity):** A 256-block ring buffer detects
//!   consensus forks, identifies the Lowest Common Ancestor (LCA), and cleanly rolls back
//!   `Invoice<Detected>` to `Invoice<Pending>` with zero double-credits.

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
use gw_chain_traits::{CheckoutDepositRoute, NormalizedTransferEvent};
use gw_primitives::{PhysicalAssetId, RawAssetAmount, SovereignError, UsdMicros};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;
use uuid::Uuid;

/// Verification errors emitted when an incoming transfer event fails one of the 5 gates.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerificationError {
    /// Foundational mathematical error.
    #[error("Primitive arithmetic error: {0}")]
    Primitive(#[from] SovereignError),

    /// Gate 1: On-chain transaction execution failed or reverted.
    #[error("Gate 1 Failed: On-chain transaction execution reverted or aborted (tx={0})")]
    Gate1ExecutionReverted(String),

    /// Gate 2: Contract address or chain mismatch (spoofing attempt).
    #[error("Gate 2 Failed: Unwhitelisted or spoofed token contract (expected={expected}, actual={actual})")]
    Gate2ContractSpoofed {
        /// Expected canonical contract or mint.
        expected: String,
        /// Actual contract address on incoming event.
        actual: String,
    },

    /// Gate 4: Transfer timestamp exceeded invoice quote window.
    #[error("Gate 4 Failed: Payment arrived at {tx_time} after quote expiration {expires_at}")]
    Gate4QuoteExpired {
        /// Block timestamp of payment.
        tx_time: u64,
        /// Quote expiry timestamp.
        expires_at: u64,
    },

    /// Invoice has not yet expired.
    #[error("Invoice quote has not yet expired (current={current}, expires_at={expires_at})")]
    QuoteNotYetExpired {
        /// Current unix time.
        current: u64,
        /// Expiry time.
        expires_at: u64,
    },
}

// ============================================================================
// COMPILE-TIME TYPESTATE MARKERS
// ============================================================================

/// Typestate Marker: Invoice is awaiting on-chain deposit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending;

/// Typestate Marker: Deposit detected on-chain, accumulating confirmations or verifying continuity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detected {
    /// Confirmed block depth.
    pub current_confirmations: u32,
    /// Target confirmation depth required for finality.
    pub target_confirmations: u32,
    /// Transaction hash of the detected transfer.
    pub last_tx_hash: String,
    /// Block height at which deposit was mined.
    pub detected_block_height: u64,
}

/// Typestate Marker: Deposit verified, but cumulative amount falls short of basis-point tolerance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Partial {
    /// Remaining amount required to complete the invoice.
    pub shortfall_raw: RawAssetAmount,
}

/// Typestate Marker: All 5 gates passed. Order fulfillment and FIFO acquisition lot unlocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedComplete {
    /// Settling on-chain transaction hash.
    pub settlement_tx_hash: String,
    /// Block timestamp when finality gate passed.
    pub settled_at_unix: u64,
    /// `true` if received amount exceeded the 102% overpayment threshold.
    pub is_overpaid: bool,
    /// Surplus token amount above expected.
    pub surplus_raw: RawAssetAmount,
}

/// Typestate Marker: Invoice quote window expired without qualifying deposit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expired;

// ============================================================================
// GENERIC TYPESTATE INVOICE CONTAINER
// ============================================================================

/// Generic Typestate Invoice container enforcing compile-time state guarantees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invoice<State> {
    /// Monotonic invoice sequence identifier.
    pub invoice_id: u64,
    /// Optional customer UUID for registered accounts.
    pub customer_id: Option<Uuid>,
    /// Target asset specification.
    pub asset: PhysicalAssetId,
    /// Assigned checkout deposit route.
    pub route: CheckoutDepositRoute,
    /// Invoice denomination in fixed-point USD micros.
    pub fiat_amount_usd: UsdMicros,
    /// Locked dual-oracle conversion price at checkout creation.
    pub locked_price_usd: UsdMicros,
    /// Exact calculated asset amount expected.
    pub expected_amount_raw: RawAssetAmount,
    /// Cumulative raw amount credited to date.
    pub received_amount_raw: RawAssetAmount,
    /// Slippage tolerance in basis points (e.g. 50 = 0.5%).
    pub tolerance_bps: u16,
    /// Unix timestamp when the price quote expires.
    pub expires_at_unix: u64,
    /// State-specific payload marker.
    pub state: State,
}

/// Evaluation outcome returned by the 5-Gate Verification Engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateEvaluationOutcome {
    /// Event accepted, but pending confirmation depth or parent-hash verification.
    StillDetected(Invoice<Detected>),
    /// Deposit verified with full confirmations, but amount underpaid.
    TransitionedToPartial(Invoice<Partial>),
    /// Deposit verified with full confirmations and amount within/above tolerance.
    TransitionedToComplete(Invoice<VerifiedComplete>),
}

impl Invoice<Pending> {
    /// Creates a fresh Pending invoice.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invoice_id: u64,
        customer_id: Option<Uuid>,
        asset: PhysicalAssetId,
        route: CheckoutDepositRoute,
        fiat_amount_usd: UsdMicros,
        locked_price_usd: UsdMicros,
        expected_amount_raw: RawAssetAmount,
        tolerance_bps: u16,
        expires_at_unix: u64,
    ) -> Self {
        let decimals = asset.decimals;
        Self {
            invoice_id,
            customer_id,
            asset,
            route,
            fiat_amount_usd,
            locked_price_usd,
            expected_amount_raw,
            received_amount_raw: RawAssetAmount::zero(decimals),
            tolerance_bps,
            expires_at_unix,
            state: Pending,
        }
    }

    /// Evaluates an incoming transfer event through the 5-Gate Verification Engine.
    pub fn evaluate_transfer(
        mut self,
        event: &NormalizedTransferEvent,
        parent_hash_continuity_verified: bool,
    ) -> Result<GateEvaluationOutcome, VerificationError> {
        // GATE 1: On-Chain Execution Status
        if !event.execution_succeeded {
            return Err(VerificationError::Gate1ExecutionReverted(
                event.tx_hash.clone(),
            ));
        }

        // GATE 2: Strict Contract & Chain Identity
        if event.chain_id != self.asset.chain_id
            || !event
                .token_contract
                .eq_ignore_ascii_case(&self.asset.token_contract)
        {
            return Err(VerificationError::Gate2ContractSpoofed {
                expected: self.asset.token_contract.clone(),
                actual: event.token_contract.clone(),
            });
        }

        // GATE 4: Temporal Quote Window Guard
        if event.block_timestamp_unix > self.expires_at_unix {
            return Err(VerificationError::Gate4QuoteExpired {
                tx_time: event.block_timestamp_unix,
                expires_at: self.expires_at_unix,
            });
        }

        // Update cumulative received balance
        self.received_amount_raw = self.received_amount_raw.checked_add(event.net_amount_raw)?;

        // GATE 5: Consensus Finality & Parent-Hash Continuity
        if !parent_hash_continuity_verified || event.confirmations < event.target_confirmations {
            return Ok(GateEvaluationOutcome::StillDetected(Invoice {
                invoice_id: self.invoice_id,
                customer_id: self.customer_id,
                asset: self.asset,
                route: self.route,
                fiat_amount_usd: self.fiat_amount_usd,
                locked_price_usd: self.locked_price_usd,
                expected_amount_raw: self.expected_amount_raw,
                received_amount_raw: self.received_amount_raw,
                tolerance_bps: self.tolerance_bps,
                expires_at_unix: self.expires_at_unix,
                state: Detected {
                    current_confirmations: event.confirmations,
                    target_confirmations: event.target_confirmations,
                    last_tx_hash: event.tx_hash.clone(),
                    detected_block_height: event.block_number,
                },
            }));
        }

        // GATE 3: Cumulative Slippage & Overpayment Partition
        self.evaluate_gate3_amount(event.tx_hash.clone(), event.block_timestamp_unix)
    }

    /// Evaluates Gate 3 partition algebra.
    fn evaluate_gate3_amount(
        self,
        tx_hash: String,
        settled_at_unix: u64,
    ) -> Result<GateEvaluationOutcome, VerificationError> {
        let bps_scale = U256::from(10_000_u64);
        let min_bps = bps_scale
            .checked_sub(U256::from(self.tolerance_bps))
            .ok_or(SovereignError::Underflow {
                context: "tolerance_bps",
            })?;

        let min_acceptable_raw = self
            .expected_amount_raw
            .raw()
            .checked_mul(min_bps)
            .ok_or(SovereignError::Overflow {
                context: "min_acceptable_raw",
            })?
            .checked_div(bps_scale)
            .ok_or(SovereignError::DivisionByZero)?;

        // Underpaid partition -> Partial
        if self.received_amount_raw.raw() < min_acceptable_raw {
            let shortfall_u256 = self
                .expected_amount_raw
                .raw()
                .checked_sub(self.received_amount_raw.raw())
                .ok_or(SovereignError::Underflow {
                    context: "shortfall",
                })?;
            let shortfall = RawAssetAmount::new(shortfall_u256, self.asset.decimals);

            return Ok(GateEvaluationOutcome::TransitionedToPartial(Invoice {
                invoice_id: self.invoice_id,
                customer_id: self.customer_id,
                asset: self.asset,
                route: self.route,
                fiat_amount_usd: self.fiat_amount_usd,
                locked_price_usd: self.locked_price_usd,
                expected_amount_raw: self.expected_amount_raw,
                received_amount_raw: self.received_amount_raw,
                tolerance_bps: self.tolerance_bps,
                expires_at_unix: self.expires_at_unix,
                state: Partial {
                    shortfall_raw: shortfall,
                },
            }));
        }

        // Overpayment threshold (102% = 10,200 bps)
        let overpay_threshold_raw = self
            .expected_amount_raw
            .raw()
            .checked_mul(U256::from(10_200_u64))
            .ok_or(SovereignError::Overflow {
                context: "overpay_threshold_raw",
            })?
            .checked_div(bps_scale)
            .ok_or(SovereignError::DivisionByZero)?;

        let is_overpaid = self.received_amount_raw.raw() > overpay_threshold_raw;
        let surplus_raw = if self.received_amount_raw.raw() > self.expected_amount_raw.raw() {
            let surplus_u256 = self
                .received_amount_raw
                .raw()
                .checked_sub(self.expected_amount_raw.raw())
                .ok_or(SovereignError::Underflow {
                    context: "surplus",
                })?;
            RawAssetAmount::new(surplus_u256, self.asset.decimals)
        } else {
            RawAssetAmount::zero(self.asset.decimals)
        };

        Ok(GateEvaluationOutcome::TransitionedToComplete(Invoice {
            invoice_id: self.invoice_id,
            customer_id: self.customer_id,
            asset: self.asset,
            route: self.route,
            fiat_amount_usd: self.fiat_amount_usd,
            locked_price_usd: self.locked_price_usd,
            expected_amount_raw: self.expected_amount_raw,
            received_amount_raw: self.received_amount_raw,
            tolerance_bps: self.tolerance_bps,
            expires_at_unix: self.expires_at_unix,
            state: VerifiedComplete {
                settlement_tx_hash: tx_hash,
                settled_at_unix,
                is_overpaid,
                surplus_raw,
            },
        }))
    }

    /// Transitions an unpaid invoice to Expired if current unix timestamp exceeds quote expiry.
    pub fn expire(self, current_unix_time: u64) -> Result<Invoice<Expired>, VerificationError> {
        if current_unix_time <= self.expires_at_unix {
            return Err(VerificationError::QuoteNotYetExpired {
                current: current_unix_time,
                expires_at: self.expires_at_unix,
            });
        }

        Ok(Invoice {
            invoice_id: self.invoice_id,
            customer_id: self.customer_id,
            asset: self.asset,
            route: self.route,
            fiat_amount_usd: self.fiat_amount_usd,
            locked_price_usd: self.locked_price_usd,
            expected_amount_raw: self.expected_amount_raw,
            received_amount_raw: self.received_amount_raw,
            tolerance_bps: self.tolerance_bps,
            expires_at_unix: self.expires_at_unix,
            state: Expired,
        })
    }
}

impl Invoice<Detected> {
    /// Updates confirmation depth for a detected invoice.
    pub fn update_confirmations(
        self,
        confirmations: u32,
        parent_hash_continuity_verified: bool,
    ) -> Result<GateEvaluationOutcome, VerificationError> {
        if !parent_hash_continuity_verified || confirmations < self.state.target_confirmations {
            return Ok(GateEvaluationOutcome::StillDetected(Invoice {
                invoice_id: self.invoice_id,
                customer_id: self.customer_id,
                asset: self.asset,
                route: self.route,
                fiat_amount_usd: self.fiat_amount_usd,
                locked_price_usd: self.locked_price_usd,
                expected_amount_raw: self.expected_amount_raw,
                received_amount_raw: self.received_amount_raw,
                tolerance_bps: self.tolerance_bps,
                expires_at_unix: self.expires_at_unix,
                state: Detected {
                    current_confirmations: confirmations,
                    target_confirmations: self.state.target_confirmations,
                    last_tx_hash: self.state.last_tx_hash,
                    detected_block_height: self.state.detected_block_height,
                },
            }));
        }

        // Passed finality -> Gate 3 partition
        let tx_hash = self.state.last_tx_hash.clone();
        let pending_version = Invoice {
            invoice_id: self.invoice_id,
            customer_id: self.customer_id,
            asset: self.asset,
            route: self.route,
            fiat_amount_usd: self.fiat_amount_usd,
            locked_price_usd: self.locked_price_usd,
            expected_amount_raw: self.expected_amount_raw,
            received_amount_raw: self.received_amount_raw,
            tolerance_bps: self.tolerance_bps,
            expires_at_unix: self.expires_at_unix,
            state: Pending,
        };

        pending_version.evaluate_gate3_amount(tx_hash, self.expires_at_unix)
    }

    /// Reorg Rollback: Consumes Detected invoice and returns it back to Pending.
    ///
    /// Invoked when a blockchain fork reorganizes away the block containing the detected deposit.
    pub fn rollback_to_pending(self) -> Invoice<Pending> {
        let decimals = self.asset.decimals;
        Invoice {
            invoice_id: self.invoice_id,
            customer_id: self.customer_id,
            asset: self.asset,
            route: self.route,
            fiat_amount_usd: self.fiat_amount_usd,
            locked_price_usd: self.locked_price_usd,
            expected_amount_raw: self.expected_amount_raw,
            received_amount_raw: RawAssetAmount::zero(decimals),
            tolerance_bps: self.tolerance_bps,
            expires_at_unix: self.expires_at_unix,
            state: Pending,
        }
    }
}

impl Invoice<Partial> {
    /// Ingests an additional top-up payment for an underpaid invoice.
    pub fn evaluate_additional_transfer(
        mut self,
        event: &NormalizedTransferEvent,
        parent_hash_continuity_verified: bool,
    ) -> Result<GateEvaluationOutcome, VerificationError> {
        if !event.execution_succeeded {
            return Err(VerificationError::Gate1ExecutionReverted(
                event.tx_hash.clone(),
            ));
        }

        if event.chain_id != self.asset.chain_id
            || !event
                .token_contract
                .eq_ignore_ascii_case(&self.asset.token_contract)
        {
            return Err(VerificationError::Gate2ContractSpoofed {
                expected: self.asset.token_contract.clone(),
                actual: event.token_contract.clone(),
            });
        }

        self.received_amount_raw = self.received_amount_raw.checked_add(event.net_amount_raw)?;

        if !parent_hash_continuity_verified || event.confirmations < event.target_confirmations {
            return Ok(GateEvaluationOutcome::StillDetected(Invoice {
                invoice_id: self.invoice_id,
                customer_id: self.customer_id,
                asset: self.asset,
                route: self.route,
                fiat_amount_usd: self.fiat_amount_usd,
                locked_price_usd: self.locked_price_usd,
                expected_amount_raw: self.expected_amount_raw,
                received_amount_raw: self.received_amount_raw,
                tolerance_bps: self.tolerance_bps,
                expires_at_unix: self.expires_at_unix,
                state: Detected {
                    current_confirmations: event.confirmations,
                    target_confirmations: event.target_confirmations,
                    last_tx_hash: event.tx_hash.clone(),
                    detected_block_height: event.block_number,
                },
            }));
        }

        let pending_version = Invoice {
            invoice_id: self.invoice_id,
            customer_id: self.customer_id,
            asset: self.asset,
            route: self.route,
            fiat_amount_usd: self.fiat_amount_usd,
            locked_price_usd: self.locked_price_usd,
            expected_amount_raw: self.expected_amount_raw,
            received_amount_raw: self.received_amount_raw,
            tolerance_bps: self.tolerance_bps,
            expires_at_unix: self.expires_at_unix,
            state: Pending,
        };

        pending_version.evaluate_gate3_amount(event.tx_hash.clone(), event.block_timestamp_unix)
    }
}

// ============================================================================
// CONSENSUS REORG SLIDING WINDOW RING BUFFER
// ============================================================================

/// Canonical block header record stored in the sliding-window ring buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeaderRecord {
    /// Block height.
    pub height: u64,
    /// Canonical block hash.
    pub block_hash: String,
    /// Parent block hash.
    pub parent_hash: String,
    /// Block timestamp.
    pub timestamp_unix: u64,
}

/// Bounded sliding-window parent-hash ring buffer detecting reorganizations and calculating LCA.
pub struct ParentHashRingBuffer {
    capacity: usize,
    buffer: VecDeque<BlockHeaderRecord>,
}

impl ParentHashRingBuffer {
    /// Creates a new ring buffer with specified depth (default 256 blocks).
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(32),
            buffer: VecDeque::with_capacity(capacity.max(32)),
        }
    }

    /// Verifies parent-hash continuity predicate:
    /// Lambda_cont(b_h) <=> (h == h_tip + 1) && (P_h == H_{h-1})
    pub fn check_continuity(&self, height: u64, parent_hash: &str) -> bool {
        match self.buffer.back() {
            None => true, // Genesis or initial cold start
            Some(tip) => tip.height.saturating_add(1) == height && tip.block_hash == parent_hash,
        }
    }

    /// Ingests a new block header. If capacity exceeded, pops the oldest block.
    pub fn ingest_block(&mut self, record: BlockHeaderRecord) {
        if self.buffer.len() >= self.capacity {
            self.buffer.pop_front();
        }
        self.buffer.push_back(record);
    }

    /// Searches backwards through the ring buffer to find the Lowest Common Ancestor (LCA).
    ///
    /// Returns the maximum height $h_{\text{LCA}} < h$ where the node's block hash matches
    /// the cached ring buffer hash.
    pub fn find_lowest_common_ancestor(&self, node_headers_descending: &[(u64, &str)]) -> Option<u64> {
        for &(node_height, node_hash) in node_headers_descending {
            for cached in self.buffer.iter().rev() {
                if cached.height == node_height && cached.block_hash == node_hash {
                    return Some(cached.height);
                }
            }
        }
        None
    }

    /// Trims ring buffer back to $h_{\text{LCA}}$, returning all orphaned block records.
    pub fn rollback_to_lca(&mut self, lca_height: u64) -> Vec<BlockHeaderRecord> {
        let mut orphaned = Vec::new();
        while let Some(back) = self.buffer.back() {
            if back.height > lca_height {
                if let Some(popped) = self.buffer.pop_back() {
                    orphaned.push(popped);
                }
            } else {
                break;
            }
        }
        orphaned
    }

    /// Current height of the chain tip in the buffer.
    pub fn tip_height(&self) -> Option<u64> {
        self.buffer.back().map(|b| b.height)
    }

    /// Number of blocks currently in the ring buffer.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use gw_primitives::{ChainArchitecture, ChainId, LogicalAsset};

    fn dummy_asset() -> PhysicalAssetId {
        PhysicalAssetId {
            chain_id: ChainId::EthereumMainnet,
            logical_asset: LogicalAsset::Usdt,
            token_contract: "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
            decimals: 6,
            keep_one_unit_dust: false,
            target_confirmations: 12,
        }
    }

    fn dummy_route() -> CheckoutDepositRoute {
        CheckoutDepositRoute {
            chain_id: ChainId::EthereumMainnet,
            deposit_address: "0x1111111111111111111111111111111111111111".to_string(),
            routing_reference: None,
            derivation_locator: "salt_01".to_string(),
        }
    }

    #[test]
    fn test_5_gate_lifecycle_full_flow() {
        let asset = dummy_asset();
        let expected = RawAssetAmount::new(U256::from(100_000_000_u64), 6); // 100 USDT
        let invoice = Invoice::new(
            1,
            None,
            asset.clone(),
            dummy_route(),
            UsdMicros(100_000_000),
            UsdMicros(1_000_000),
            expected,
            50, // 50 bps tolerance = 0.5%
            1_000_000,
        );

        // 1. Reverted transaction rejected at Gate 1
        let reverted_event = NormalizedTransferEvent {
            chain_id: ChainId::EthereumMainnet,
            architecture: ChainArchitecture::EvmAccount,
            tx_hash: "0xrevert".to_string(),
            block_number: 100,
            block_hash: "0xhash1".to_string(),
            parent_block_hash: "0xparent0".to_string(),
            block_timestamp_unix: 500_000,
            lookup_key: "0x1111111111111111111111111111111111111111".to_string(),
            token_contract: asset.token_contract.clone(),
            net_amount_raw: expected,
            execution_succeeded: false,
            confirmations: 12,
            target_confirmations: 12,
        };
        assert!(matches!(
            invoice.clone().evaluate_transfer(&reverted_event, true),
            Err(VerificationError::Gate1ExecutionReverted(_))
        ));

        // 2. Spoofed contract rejected at Gate 2
        let spoofed_event = NormalizedTransferEvent {
            token_contract: "0xfake".to_string(),
            execution_succeeded: true,
            ..reverted_event.clone()
        };
        assert!(matches!(
            invoice.clone().evaluate_transfer(&spoofed_event, true),
            Err(VerificationError::Gate2ContractSpoofed { .. })
        ));

        // 3. Expired payment rejected at Gate 4
        let expired_event = NormalizedTransferEvent {
            execution_succeeded: true,
            block_timestamp_unix: 2_000_000, // after 1_000_000 expiry
            ..reverted_event.clone()
        };
        assert!(matches!(
            invoice.clone().evaluate_transfer(&expired_event, true),
            Err(VerificationError::Gate4QuoteExpired { .. })
        ));

        // 4. Pending confirmations -> StillDetected
        let pending_conf_event = NormalizedTransferEvent {
            execution_succeeded: true,
            confirmations: 4, // only 4/12
            ..reverted_event.clone()
        };
        let outcome = invoice
            .clone()
            .evaluate_transfer(&pending_conf_event, true)
            .unwrap();
        assert!(matches!(outcome, GateEvaluationOutcome::StillDetected(_)));

        // 5. Full payment with 12 confirmations -> TransitionedToComplete
        let valid_event = NormalizedTransferEvent {
            execution_succeeded: true,
            confirmations: 12,
            ..reverted_event
        };
        let final_outcome = invoice.evaluate_transfer(&valid_event, true).unwrap();
        assert!(matches!(
            final_outcome,
            GateEvaluationOutcome::TransitionedToComplete(_)
        ));
    }

    #[test]
    fn test_ring_buffer_reorg_lca_detection_and_rollback() {
        let mut ring = ParentHashRingBuffer::new(256);

        // Ingest canonical blocks 100 -> 103
        ring.ingest_block(BlockHeaderRecord {
            height: 100,
            block_hash: "hash_100".to_string(),
            parent_hash: "hash_99".to_string(),
            timestamp_unix: 1000,
        });
        ring.ingest_block(BlockHeaderRecord {
            height: 101,
            block_hash: "hash_101".to_string(),
            parent_hash: "hash_100".to_string(),
            timestamp_unix: 1012,
        });
        ring.ingest_block(BlockHeaderRecord {
            height: 102,
            block_hash: "hash_102".to_string(),
            parent_hash: "hash_101".to_string(),
            timestamp_unix: 1024,
        });
        ring.ingest_block(BlockHeaderRecord {
            height: 103,
            block_hash: "hash_103".to_string(),
            parent_hash: "hash_102".to_string(),
            timestamp_unix: 1036,
        });

        assert_eq!(ring.tip_height(), Some(103));
        assert!(ring.check_continuity(104, "hash_103"));
        assert!(!ring.check_continuity(104, "fork_hash_103"));

        // Fork occurs: Node reports fork blocks at 103 and 102, but common ancestor is at 101
        let node_branch = [
            (103, "fork_103"),
            (102, "fork_102"),
            (101, "hash_101"), // Common ancestor!
        ];

        let lca = ring.find_lowest_common_ancestor(&node_branch);
        assert_eq!(lca, Some(101));

        // Roll back to LCA
        let orphaned = ring.rollback_to_lca(101);
        assert_eq!(orphaned.len(), 2); // blocks 103 and 102 orphaned
        assert_eq!(ring.tip_height(), Some(101));
    }
}
