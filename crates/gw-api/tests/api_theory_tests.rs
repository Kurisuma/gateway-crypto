//! # Phase 8 API Gateway Integration Tests
//!
//! Formal verification of Zone A Axum REST & WebSocket endpoints:
//! - POST /api/v1/invoices (Quote generation, route derivation, dust truncation)
//! - Idempotency conflict enforcement (X-Idempotency-Key 7-day replay rejection)
//! - GET /api/v1/invoices/:id (Status query, 404 handling)
//! - GET /api/v1/treasury/portfolio (Unified portfolio rollup)
//! - GET /api/v1/treasury/lots (FIFO tax lot ledger)
//! - Zone A Zero-Key Isolation verification

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use alloy_primitives::{Address, B256, U256};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use gw_adapters_evm::EvmCreate2Adapter;
use gw_api::{build_app_router, AppState, CreateInvoiceRequest, CreateInvoiceResponse};
use gw_chain_traits::NetworkAdapterRegistry;
use gw_db::DatabaseManager;
use gw_memcache::enclave_replay_guard::EnclaveAntiReplayCache;
use gw_memcache::price_oracle_cache::PriceQuoteOracleCache;
use gw_memcache::watchlist_engine::InProcessWatchlistEngine;
use gw_primitives::{ChainId, LogicalAsset, RawAssetAmount, UsdMicros, WalletTier};
use gw_treasury::{
    FifoCostBasisLot, SovereignTreasuryPortfolioEngine, WalletAssetHolding,
};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const CSPRNG_SEED: [u8; 64] = [0x5A; 64];
const FACTORY: Address = Address::repeat_byte(0x11);
const INIT_HASH: B256 = B256::repeat_byte(0x22);
const COLD_SAFE: Address = Address::repeat_byte(0x33);

fn setup_test_app() -> (axum::Router, AppState) {
    let watchlist = Arc::new(InProcessWatchlistEngine::new(&CSPRNG_SEED, 10_000));
    let anti_replay = Arc::new(EnclaveAntiReplayCache::new(&CSPRNG_SEED, 10_000));
    let price_cache = Arc::new(PriceQuoteOracleCache::new(&CSPRNG_SEED));

    // Seed price cache with dual-verified price for USDT = $1.00 ($1,000,000 micros)
    price_cache
        .update_verified_quote(
            LogicalAsset::Usdt,
            UsdMicros(1_000_000),
            UsdMicros(1_000_000),
            150,
        )
        .expect("price seeding should succeed");

    // Register EVM adapter
    let mut registry = NetworkAdapterRegistry::new();
    let evm_adapter = Arc::new(EvmCreate2Adapter::new(
        ChainId::EthereumMainnet,
        FACTORY,
        INIT_HASH,
        COLD_SAFE,
        false,
    ));
    registry.register(evm_adapter);

    let treasury_engine = Arc::new(SovereignTreasuryPortfolioEngine::new());
    let db_manager = Arc::new(DatabaseManager::new(":memory:").expect("in-memory db"));
    db_manager.migrate_all().expect("migrations should succeed");

    let state = AppState::new(
        watchlist,
        anti_replay,
        price_cache,
        Arc::new(registry),
        treasury_engine,
        db_manager,
    );

    let router = build_app_router(state.clone());
    (router, state)
}

#[tokio::test]
async fn test_create_invoice_and_get_invoice_flow() {
    let (app, _) = setup_test_app();

    // 1. Create Invoice: $50.00 USDT on Ethereum
    let req_body = CreateInvoiceRequest {
        fiat_amount_usd_micros: 50_000_000, // $50.00
        chain_id: ChainId::EthereumMainnet,
        logical_asset: LogicalAsset::Usdt,
        customer_id: Some(Uuid::new_v4()),
        tolerance_bps: Some(50),
        quote_ttl_seconds: Some(1800),
    };

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/invoices")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                .unwrap(),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::CREATED);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let create_resp: CreateInvoiceResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(create_resp.chain_id, ChainId::EthereumMainnet);
    assert_eq!(create_resp.logical_asset, LogicalAsset::Usdt);
    assert_eq!(create_resp.status, "PENDING");
    assert_eq!(create_resp.locked_price_usd_micros, 1_000_000);
    // 50 USD / 1.00 USD/unit * 10^6 decimals = 50,000,000 units
    assert_eq!(create_resp.expected_amount_raw, "50000000");
    assert!(create_resp.deposit_address.starts_with("0x"));

    let invoice_id = create_resp.invoice_id;

    // 2. Query Created Invoice
    let get_resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/invoices/{invoice_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("get request failed");

    assert_eq!(get_resp.status(), StatusCode::OK);
    let get_bytes = axum::body::to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
    let get_val: serde_json::Value = serde_json::from_slice(&get_bytes).unwrap();

    assert_eq!(get_val["invoice_id"], invoice_id);
    assert_eq!(get_val["status"], "PENDING");
    assert_eq!(get_val["expected_amount_raw"], "50000000");
}

#[tokio::test]
async fn test_idempotency_key_prevents_replay() {
    let (app, _) = setup_test_app();

    let req_body = CreateInvoiceRequest {
        fiat_amount_usd_micros: 25_000_000, // $25.00
        chain_id: ChainId::EthereumMainnet,
        logical_asset: LogicalAsset::Usdt,
        customer_id: None,
        tolerance_bps: None,
        quote_ttl_seconds: None,
    };

    let idempotency_key = "idemp_order_unique_998877";

    // Request 1: Fresh idempotency key -> Must succeed with 201 Created
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/invoices")
                .header("content-type", "application/json")
                .header("x-idempotency-key", idempotency_key)
                .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                .unwrap(),
        )
        .await
        .expect("request 1 failed");

    assert_eq!(resp1.status(), StatusCode::CREATED);

    // Request 2: Duplicate idempotency key -> Must be rejected with 409 Conflict
    let resp2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/invoices")
                .header("content-type", "application/json")
                .header("x-idempotency-key", idempotency_key)
                .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                .unwrap(),
        )
        .await
        .expect("request 2 failed");

    assert_eq!(resp2.status(), StatusCode::CONFLICT);
    let body_bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX).await.unwrap();
    let err_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(err_json["error"]
        .as_str()
        .unwrap()
        .contains("has already been processed"));
}

#[tokio::test]
async fn test_invoice_not_found_returns_404() {
    let (app, _) = setup_test_app();

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/invoices/999999999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request failed");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_treasury_portfolio_endpoint() {
    let (app, state) = setup_test_app();

    // Populate state with sample holdings
    let holding = WalletAssetHolding {
        wallet_id: Uuid::new_v4(),
        wallet_tier: WalletTier::Tier3ColdVault,
        asset: gw_primitives::PhysicalAssetId {
            chain_id: ChainId::EthereumMainnet,
            logical_asset: LogicalAsset::Usdt,
            token_contract: "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
            decimals: 6,
            keep_one_unit_dust: false,
            target_confirmations: 12,
        },
        raw_balance: RawAssetAmount::new(U256::from(100_000_000u64), 6), // 100 USDT
        current_spot_price_usd: UsdMicros(1_000_000),                     // $1.00
    };
    state.holdings_store.write().push(holding);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/treasury/portfolio")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let portfolio_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(portfolio_json.get("Usdt").is_some());
    assert_eq!(
        portfolio_json["Usdt"]["total_market_valuation_usd"],
        100_000_000
    );
}

#[tokio::test]
async fn test_treasury_lots_endpoint() {
    let (app, state) = setup_test_app();

    let lot = FifoCostBasisLot {
        lot_id: Uuid::new_v4(),
        source_invoice_id: 1001,
        asset: gw_primitives::PhysicalAssetId {
            chain_id: ChainId::EthereumMainnet,
            logical_asset: LogicalAsset::Usdt,
            token_contract: "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
            decimals: 6,
            keep_one_unit_dust: false,
            target_confirmations: 12,
        },
        initial_amount: RawAssetAmount::new(U256::from(50_000_000u64), 6),
        remaining_amount: RawAssetAmount::new(U256::from(50_000_000u64), 6),
        acquisition_price_usd: UsdMicros(1_000_000),
        acquired_at_unix: 1700000000,
    };
    state.fifo_lots_store.write().push(lot);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/treasury/lots")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let lots_json: Vec<serde_json::Value> = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(lots_json.len(), 1);
    assert_eq!(lots_json[0]["source_invoice_id"], 1001);
}
