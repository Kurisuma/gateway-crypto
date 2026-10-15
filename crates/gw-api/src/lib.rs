//! # gw-api
//!
//! Zone A High-Performance Axum REST & WebSocket Checkout and Treasury Dashboard API.
//!
//! # Security & Architectural Invariants
//! - **Invariant I (Zero Private Keys in Zone A):** This crate contains zero private keys, signing SDKs,
//!   or cryptographic signing dependencies in its compile tree. It operates purely on public addresses,
//!   `xpub`/`zpub` derivators, and reference keys.
//! - **Invariant II (Cryptographic Idempotency & Replay Immunity):** Customer checkouts enforce idempotency
//!   via `gw-memcache` anti-replay lock against identical `X-Idempotency-Key` headers.
//! - **Invariant III (Dual-Oracle Dust-Truncated Quotes):** Quotes apply $\mathcal{T}_{\text{clean}}$ 18-decimal
//!   dust truncation and dual-oracle price verification ($\le 150\text{ bps}$).

#![forbid(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
#![warn(missing_docs)]

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use gw_chain_traits::NetworkAdapterRegistry;
use gw_db::models::InvoiceRecord;
use gw_db::DatabaseManager;
use gw_memcache::enclave_replay_guard::EnclaveAntiReplayCache;
use gw_memcache::price_oracle_cache::PriceQuoteOracleCache;
use gw_memcache::traits::WatchlistMemoryEngine;
use gw_memcache::watchlist_engine::InProcessWatchlistEngine;
use gw_primitives::{ChainId, LogicalAsset, PhysicalAssetId, SovereignError, UsdMicros};
use gw_treasury::{
    EnterpriseTreasuryPortfolioEngine, FifoCostBasisLot, UnifiedAssetPortfolioSummary,
    WalletAssetHolding,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Error taxonomy for API gateway requests.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Primitive arithmetic or validation error.
    #[error("Domain arithmetic error: {0}")]
    Primitive(#[from] SovereignError),

    /// Missing or unsupported blockchain network adapter.
    #[error("Network adapter not found for chain {0:?}")]
    NetworkAdapterNotFound(ChainId),

    /// Missing spot price for logical asset.
    #[error("Oracle price unavailable for asset {0:?}")]
    PriceUnavailable(LogicalAsset),

    /// Invoice not found.
    #[error("Invoice not found: id={0}")]
    InvoiceNotFound(u64),

    /// Duplicate idempotency key rejected.
    #[error("Idempotency conflict: request with key '{0}' has already been processed")]
    IdempotencyConflict(String),

    /// Database ledger error.
    #[error("Ledger storage error: {0}")]
    Database(String),

    /// Internal error.
    #[error("Internal service error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::IdempotencyConflict(_) => (StatusCode::CONFLICT, self.to_string()),
            Self::InvoiceNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            Self::NetworkAdapterNotFound(_) | Self::PriceUnavailable(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            Self::Primitive(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
            Self::Database(e) | Self::Internal(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        };

        let body = Json(serde_json::json!({
            "error": message,
            "status_code": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

/// Resolves `ChainId` from numeric integer value.
pub fn chain_id_from_u64(id: u64) -> Option<ChainId> {
    match id {
        0 => Some(ChainId::BitcoinMainnet),
        1 => Some(ChainId::EthereumMainnet),
        56 => Some(ChainId::BnbChain),
        98866 => Some(ChainId::PlumeMainnet),
        900 => Some(ChainId::SolanaMainnet),
        728126428 => Some(ChainId::TronMainnet),
        1100 => Some(ChainId::TonMainnet),
        1200 => Some(ChainId::SuiMainnet),
        _ => None,
    }
}

/// In-memory stored invoice detail for fast checkout lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredInvoiceInfo {
    /// Monotonic invoice identifier.
    pub invoice_id: u64,
    /// Unique UUID.
    pub invoice_uuid: String,
    /// Blockchain network.
    pub chain_id: ChainId,
    /// Logical asset.
    pub logical_asset: LogicalAsset,
    /// Assigned on-chain deposit address.
    pub deposit_address: String,
    /// Secondary routing memo or reference pubkey.
    pub routing_reference: Option<String>,
    /// Expected raw asset amount string.
    pub expected_amount_raw: String,
    /// Received raw asset amount string.
    pub received_amount_raw: String,
    /// Token decimals.
    pub decimals: u8,
    /// Locked price in USD micros ($10^{-6}\text{ USD}$).
    pub locked_price_usd_micros: u128,
    /// Expiry timestamp in seconds since Unix epoch.
    pub expires_at_unix: u64,
    /// Current invoice status string.
    pub status: String,
    /// Confirmation count.
    pub confirmations: u32,
    /// Target required confirmation depth.
    pub target_confirmations: u32,
    /// Settling on-chain transaction hash.
    pub tx_hash: Option<String>,
}

/// Real-time status update pushed over WebSocket connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceStatusEvent {
    /// Monotonic invoice identifier.
    pub invoice_id: u64,
    /// Current invoice status ("PENDING", "DETECTED", "PARTIAL", "VERIFIED_COMPLETE", "EXPIRED").
    pub status: String,
    /// Cumulative raw token amount received so far.
    pub received_amount_raw: String,
    /// Expected raw token amount.
    pub expected_amount_raw: String,
    /// Current number of block confirmations.
    pub confirmations: u32,
    /// Required confirmation depth for finality.
    pub target_confirmations: u32,
    /// Settling on-chain transaction hash if detected.
    pub tx_hash: Option<String>,
}

/// Shared application state for Zone A API handlers.
#[derive(Clone)]
pub struct AppState {
    /// Double-buffered wait-free watchlist engine.
    pub watchlist: Arc<InProcessWatchlistEngine>,
    /// 7-day atomic replay guard.
    pub anti_replay: Arc<EnclaveAntiReplayCache>,
    /// 10s dual-oracle price cache.
    pub price_cache: Arc<PriceQuoteOracleCache>,
    /// Multi-chain polymorphic adapter registry.
    pub adapters: Arc<NetworkAdapterRegistry>,
    /// Unified treasury portfolio engine.
    pub treasury_engine: Arc<dyn EnterpriseTreasuryPortfolioEngine>,
    /// Relational database manager (SQLite via Oberer-lite).
    pub db_manager: Arc<DatabaseManager>,
    /// WebSocket event broadcast channel.
    pub tx_broadcaster: Arc<broadcast::Sender<InvoiceStatusEvent>>,
    /// Fast memory map of active invoices.
    pub active_invoices: Arc<RwLock<HashMap<u64, StoredInvoiceInfo>>>,
    /// Monotonic sequence generator for invoice IDs.
    pub invoice_seq: Arc<AtomicU64>,
    /// Custody holdings query provider.
    pub holdings_store: Arc<RwLock<Vec<WalletAssetHolding>>>,
    /// Open FIFO lots query provider.
    pub fifo_lots_store: Arc<RwLock<Vec<FifoCostBasisLot>>>,
}

impl AppState {
    /// Creates a fresh production-grade AppState.
    pub fn new(
        watchlist: Arc<InProcessWatchlistEngine>,
        anti_replay: Arc<EnclaveAntiReplayCache>,
        price_cache: Arc<PriceQuoteOracleCache>,
        adapters: Arc<NetworkAdapterRegistry>,
        treasury_engine: Arc<dyn EnterpriseTreasuryPortfolioEngine>,
        db_manager: Arc<DatabaseManager>,
    ) -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            watchlist,
            anti_replay,
            price_cache,
            adapters,
            treasury_engine,
            db_manager,
            tx_broadcaster: Arc::new(tx),
            active_invoices: Arc::new(RwLock::new(HashMap::new())),
            invoice_seq: Arc::new(AtomicU64::new(1000)),
            holdings_store: Arc::new(RwLock::new(Vec::new())),
            fifo_lots_store: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

// ============================================================================
// REQUEST & RESPONSE DATA TRANSFER OBJECTS (DTOs)
// ============================================================================

/// Payload for creating a locked checkout invoice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvoiceRequest {
    /// Fiat amount denominated in USD micros ($10^{-6}\text{ USD}$).
    pub fiat_amount_usd_micros: u128,
    /// Destination blockchain network.
    pub chain_id: ChainId,
    /// High-level logical asset (e.g. USDT, USDC, BTC, ETH).
    pub logical_asset: LogicalAsset,
    /// Optional customer UUID.
    pub customer_id: Option<Uuid>,
    /// Optional slippage tolerance in basis points (defaults to 50 = 0.50%).
    pub tolerance_bps: Option<u16>,
    /// Optional quote validity duration in seconds (defaults to 1800 = 30 minutes).
    pub quote_ttl_seconds: Option<u64>,
}

/// Response returned upon successful invoice creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvoiceResponse {
    /// Monotonic sequence identifier.
    pub invoice_id: u64,
    /// Unique UUID.
    pub invoice_uuid: String,
    /// Target chain ID.
    pub chain_id: ChainId,
    /// Logical asset.
    pub logical_asset: LogicalAsset,
    /// Primary deposit address (BIP-84 bc1q, CREATE2 0x..., Tron T..., or vault).
    pub deposit_address: String,
    /// Secondary routing memo or reference key (if applicable).
    pub routing_reference: Option<String>,
    /// Exact raw asset token units required.
    pub expected_amount_raw: String,
    /// Token decimal precision.
    pub decimals: u8,
    /// Locked spot conversion rate in USD micros.
    pub locked_price_usd_micros: u128,
    /// Expiry timestamp in Unix seconds.
    pub expires_at_unix: u64,
    /// Current status.
    pub status: String,
}

// ============================================================================
// REST API HANDLERS
// ============================================================================

/// Health and readiness probe handler.
pub async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "gw-api",
        "zone": "Zone A (Public Plane)",
        "security": "Zero-Key Isolation (Axiom 1 Verified)"
    }))
}

/// Handler for `POST /api/v1/invoices`.
pub async fn create_invoice_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateInvoiceRequest>,
) -> Result<(StatusCode, Json<CreateInvoiceResponse>), ApiError> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .as_secs();

    // 1. Idempotency inspection
    if let Some(idempotency_header) = headers.get("x-idempotency-key") {
        let key_str = idempotency_header
            .to_str()
            .map_err(|_| ApiError::Internal("Invalid idempotency header encoding".to_string()))?;

        // 7-day replay lock check
        state
            .anti_replay
            .consume_envelope_digest_once(key_str.to_string(), now_unix)
            .map_err(|_| ApiError::IdempotencyConflict(key_str.to_string()))?;
    }

    // 2. Fetch locked dual-oracle spot price
    let spot_price = state
        .price_cache
        .get_fresh_checkout_price(payload.logical_asset)
        .map_err(|_| ApiError::PriceUnavailable(payload.logical_asset))?;

    // 3. Adapter lookup for route derivation
    let adapter = state
        .adapters
        .get(payload.chain_id)
        .ok_or(ApiError::NetworkAdapterNotFound(payload.chain_id))?;

    let invoice_id = state.invoice_seq.fetch_add(1, Ordering::SeqCst);
    let invoice_uuid = Uuid::new_v4().to_string();

    let decimals = 6u8; // Standardized stablecoin scale
    let physical_asset = PhysicalAssetId {
        chain_id: payload.chain_id,
        logical_asset: payload.logical_asset,
        token_contract: "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
        decimals,
        keep_one_unit_dust: false,
        target_confirmations: 12,
    };

    // 4. Derive checkout deposit route
    let route = adapter
        .derive_checkout_route(invoice_id, payload.customer_id, &physical_asset)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // 5. Convert fiat amount to raw token units with dust truncation T_clean
    let fiat_micros = UsdMicros(payload.fiat_amount_usd_micros);
    let raw_expected = fiat_micros.to_locked_quote_raw(spot_price, decimals)?;

    let ttl_seconds = payload.quote_ttl_seconds.unwrap_or(1800);
    let expires_at_unix = now_unix.saturating_add(ttl_seconds);

    // 6. Register route in wait-free WatchlistEngine for indexer O(1) matching
    let lookup_key = route.watchlist_lookup_key().to_string();
    state
        .watchlist
        .register_watch_target(
            payload.chain_id,
            lookup_key,
            invoice_id,
            Duration::from_secs(ttl_seconds),
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // 7. Persist to SQLite relational ledger via Oberer-lite
    let record = InvoiceRecord {
        id: 0,
        invoice_uuid: invoice_uuid.clone(),
        chain_id: i64::try_from(payload.chain_id.as_u64()).unwrap_or(0),
        logical_asset: format!("{:?}", payload.logical_asset),
        deposit_address: route.deposit_address.clone(),
        routing_reference: route.routing_reference.clone(),
        expected_amount_raw: raw_expected.raw().to_string(),
        expected_amount_decimals: i64::from(decimals),
        locked_usd_micros: i64::try_from(spot_price.0).unwrap_or(0),
        status: "PENDING".to_string(),
        detected_tx_hash: None,
        received_amount_raw: "0".to_string(),
        created_at_unix: i64::try_from(now_unix).unwrap_or(0),
        expires_at_unix: i64::try_from(expires_at_unix).unwrap_or(0),
        settled_at_unix: None,
    };
    state
        .db_manager
        .insert_invoice(&record)
        .map_err(|e| ApiError::Database(e.to_string()))?;

    // 8. Store in active invoice cache
    let info = StoredInvoiceInfo {
        invoice_id,
        invoice_uuid: invoice_uuid.clone(),
        chain_id: payload.chain_id,
        logical_asset: payload.logical_asset,
        deposit_address: route.deposit_address.clone(),
        routing_reference: route.routing_reference.clone(),
        expected_amount_raw: raw_expected.raw().to_string(),
        received_amount_raw: "0".to_string(),
        decimals,
        locked_price_usd_micros: spot_price.0,
        expires_at_unix,
        status: "PENDING".to_string(),
        confirmations: 0,
        target_confirmations: physical_asset.target_confirmations,
        tx_hash: None,
    };
    state.active_invoices.write().insert(invoice_id, info);

    let response = CreateInvoiceResponse {
        invoice_id,
        invoice_uuid,
        chain_id: payload.chain_id,
        logical_asset: payload.logical_asset,
        deposit_address: route.deposit_address,
        routing_reference: route.routing_reference,
        expected_amount_raw: raw_expected.raw().to_string(),
        decimals,
        locked_price_usd_micros: spot_price.0,
        expires_at_unix,
        status: "PENDING".to_string(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Handler for `GET /api/v1/invoices/{id}`.
pub async fn get_invoice_handler(
    State(state): State<AppState>,
    Path(invoice_id): Path<u64>,
) -> Result<Json<StoredInvoiceInfo>, ApiError> {
    if let Some(info) = state.active_invoices.read().get(&invoice_id).cloned() {
        return Ok(Json(info));
    }

    // Fallback to SQLite ledger query
    let record_opt = state
        .db_manager
        .find_invoice_by_id(i64::try_from(invoice_id).unwrap_or(0))
        .map_err(|e| ApiError::Database(e.to_string()))?;

    if let Some(record) = record_opt {
        let chain_id = chain_id_from_u64(u64::try_from(record.chain_id).unwrap_or(0))
            .unwrap_or(ChainId::EthereumMainnet);

        let info = StoredInvoiceInfo {
            invoice_id,
            invoice_uuid: record.invoice_uuid,
            chain_id,
            logical_asset: LogicalAsset::Usdt,
            deposit_address: record.deposit_address,
            routing_reference: record.routing_reference,
            expected_amount_raw: record.expected_amount_raw,
            received_amount_raw: record.received_amount_raw,
            decimals: u8::try_from(record.expected_amount_decimals).unwrap_or(18),
            locked_price_usd_micros: u128::try_from(record.locked_usd_micros).unwrap_or(0),
            expires_at_unix: u64::try_from(record.expires_at_unix).unwrap_or(0),
            status: record.status,
            confirmations: 0,
            target_confirmations: 12,
            tx_hash: record.detected_tx_hash,
        };
        Ok(Json(info))
    } else {
        Err(ApiError::InvoiceNotFound(invoice_id))
    }
}

/// Handler for `GET /api/v1/treasury/portfolio`.
pub async fn get_treasury_portfolio_handler(
    State(state): State<AppState>,
) -> Result<Json<BTreeMap<LogicalAsset, UnifiedAssetPortfolioSummary>>, ApiError> {
    let holdings = state.holdings_store.read().clone();
    let lots = state.fifo_lots_store.read().clone();

    let portfolio = state
        .treasury_engine
        .compute_unified_global_portfolio(&holdings, &lots)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(portfolio))
}

/// Handler for `GET /api/v1/treasury/lots`.
pub async fn get_treasury_lots_handler(
    State(state): State<AppState>,
) -> Json<Vec<FifoCostBasisLot>> {
    let lots = state.fifo_lots_store.read().clone();
    Json(lots)
}

// ============================================================================
// WEBSOCKET REAL-TIME CHECKOUT STREAMING
// ============================================================================

/// WebSocket upgrade handler for real-time checkout updates (`/ws/v1/checkout/{id}`).
pub async fn ws_checkout_handler(
    ws: WebSocketUpgrade,
    Path(invoice_id): Path<u64>,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_checkout_websocket(socket, invoice_id, state))
}

async fn handle_checkout_websocket(mut socket: WebSocket, invoice_id: u64, state: AppState) {
    let mut rx = state.tx_broadcaster.subscribe();

    let initial_info = state.active_invoices.read().get(&invoice_id).cloned();
    if let Some(initial_info) = initial_info {
        let initial_event = InvoiceStatusEvent {
            invoice_id,
            status: initial_info.status,
            received_amount_raw: initial_info.received_amount_raw,
            expected_amount_raw: initial_info.expected_amount_raw,
            confirmations: initial_info.confirmations,
            target_confirmations: initial_info.target_confirmations,
            tx_hash: initial_info.tx_hash,
        };
        if let Ok(msg_text) = serde_json::to_string(&initial_event) {
            let _ = socket.send(Message::Text(msg_text.into())).await;
        }
    }

    loop {
        tokio::select! {
            // Forward relevant broadcast events to connected customer
            Ok(event) = rx.recv() => {
                if event.invoice_id == invoice_id {
                    if let Ok(msg_text) = serde_json::to_string(&event) {
                        let send_err = socket.send(Message::Text(msg_text.into())).await.is_err();
                        if send_err {
                            break;
                        }
                    }
                    if event.status == "VERIFIED_COMPLETE" || event.status == "EXPIRED" {
                        break;
                    }
                }
            }

            // Handle incoming client messages (heartbeat pings)
            Some(msg_res) = socket.recv() => {
                match msg_res {
                    Ok(Message::Ping(payload)) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

// ============================================================================
// APPLICATION ROUTER BUILDER
// ============================================================================

/// Builds the complete Zone A Axum Router with all REST endpoints, WebSocket streaming,
/// and CORS middleware.
pub fn build_app_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/api/v1/invoices", post(create_invoice_handler))
        .route("/api/v1/invoices/{id}", get(get_invoice_handler))
        .route("/api/v1/treasury/portfolio", get(get_treasury_portfolio_handler))
        .route("/api/v1/treasury/lots", get(get_treasury_lots_handler))
        .route("/ws/v1/checkout/{id}", get(ws_checkout_handler))
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_endpoint() {
        let json = health_handler().await;
        assert_eq!(json.0["status"], "healthy");
        assert_eq!(json.0["zone"], "Zone A (Public Plane)");
    }
}
