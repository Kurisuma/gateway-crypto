//! # gw-db
//!
//! Enterprise SQLite Relational Ledger & ORM Storage Engine for the Unified Crypto Gateway
//! and Treasury system, built on `oberer-orm`.
//!
//! # Responsibilities
//! - Strongly-typed SQLite relational tables for invoices, supported assets, address pools,
//!   treasury wallets, FIFO cost-basis tax lots, and realized P&L records.
//! - Sub-10ms cold-start hydration into the in-memory double-buffered watchlist (`InProcessWatchlistEngine`).
//! - Thread-safe SQLite connection queue model via `OrmConn`.

#![deny(
    clippy::float_arithmetic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
#![warn(missing_docs)]

pub mod models;

use gw_memcache::watchlist_engine::InProcessWatchlistEngine;
use gw_memcache::traits::WatchlistMemoryEngine;
use gw_primitives::ChainId;
use models::{
    CostBasisLotRecord, DepositAddressPoolRecord, InvoiceRecord, RealizedPnlRecord,
    SupportedAssetRecord, TreasuryWalletRecord,
};
use oberer_orm::{OrmConn, OrmResultExt, Table, TableOps};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Database error taxonomy for SQLite ORM operations.
#[derive(Debug, Error)]
pub enum DbError {
    /// Failure during SQLite connection initialization or command execution.
    #[error("Database ORM error: {0}")]
    Orm(String),

    /// Requested record not found.
    #[error("Record not found: {0}")]
    NotFound(String),

    /// Failed to hydrate memory cache from database.
    #[error("Cache hydration error: {0}")]
    HydrationFailed(String),

    /// System time error.
    #[error("System time error: {0}")]
    SystemTime(String),
}

/// Central database manager encapsulating SQLite connection and table operations.
#[derive(Clone)]
pub struct DatabaseManager {
    conn: OrmConn,
}

impl DatabaseManager {
    /// Opens or creates an SQLite database connection at the specified path (or `":memory:"`).
    pub fn new(database_path: &str) -> Result<Self, DbError> {
        let conn = OrmConn::new(database_path)
            .map_err(|e| DbError::Orm(format!("Failed to connect to SQLite at '{database_path}': {e}")))?;
        Ok(Self { conn })
    }

    /// Returns a cloned handle to the underlying `OrmConn`.
    pub fn conn(&self) -> &OrmConn {
        &self.conn
    }

    /// Automatically executes migrations for all tables, creating schemas and indexes.
    pub fn migrate_all(&self) -> Result<(), DbError> {
        Table::<SupportedAssetRecord>::new(self.conn.clone())
            .migrate()
            .unenvelope()
            .map_err(|e| DbError::Orm(format!("Failed to migrate SupportedAssetRecord: {e}")))?;

        Table::<DepositAddressPoolRecord>::new(self.conn.clone())
            .migrate()
            .unenvelope()
            .map_err(|e| DbError::Orm(format!("Failed to migrate DepositAddressPoolRecord: {e}")))?;

        Table::<InvoiceRecord>::new(self.conn.clone())
            .migrate()
            .unenvelope()
            .map_err(|e| DbError::Orm(format!("Failed to migrate InvoiceRecord: {e}")))?;

        Table::<TreasuryWalletRecord>::new(self.conn.clone())
            .migrate()
            .unenvelope()
            .map_err(|e| DbError::Orm(format!("Failed to migrate TreasuryWalletRecord: {e}")))?;

        Table::<CostBasisLotRecord>::new(self.conn.clone())
            .migrate()
            .unenvelope()
            .map_err(|e| DbError::Orm(format!("Failed to migrate CostBasisLotRecord: {e}")))?;

        Table::<RealizedPnlRecord>::new(self.conn.clone())
            .migrate()
            .unenvelope()
            .map_err(|e| DbError::Orm(format!("Failed to migrate RealizedPnlRecord: {e}")))?;

        Ok(())
    }

    /// Performs cold-start hydration into `InProcessWatchlistEngine` in under 10ms.
    ///
    /// Reads all active checkout invoices where `status IN ('PENDING', 'DETECTED', 'PARTIAL')`
    /// and `expires_at_unix > now`, registering their lookup keys directly into the in-memory cache.
    pub fn hydrate_watchlist(
        &self,
        watchlist_engine: &InProcessWatchlistEngine,
    ) -> Result<usize, DbError> {
        let now_unix = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DbError::SystemTime(e.to_string()))?
                .as_secs(),
        )
        .unwrap_or(0);

        let table = Table::<InvoiceRecord>::new(self.conn.clone());
        let all_invoices = table
            .find_all()
            .unenvelope()
            .map_err(|e| DbError::Orm(format!("Failed to query invoices for hydration: {e}")))?;

        let mut hydrated_count: usize = 0;
        for inv in all_invoices {
            let is_active = matches!(inv.status.as_str(), "PENDING" | "DETECTED" | "PARTIAL");
            if is_active && inv.expires_at_unix > now_unix {
                let remaining_secs = u64::try_from(inv.expires_at_unix.saturating_sub(now_unix)).unwrap_or(0);
                if remaining_secs > 0 {
                    let chain_id = match inv.chain_id {
                        0 => ChainId::BitcoinMainnet,
                        1 => ChainId::EthereumMainnet,
                        56 => ChainId::BnbChain,
                        98866 => ChainId::PlumeMainnet,
                        900 => ChainId::SolanaMainnet,
                        728126428 => ChainId::TronMainnet,
                        1100 => ChainId::TonMainnet,
                        1200 => ChainId::SuiMainnet,
                        _ => continue,
                    };

                    let lookup_key = inv
                        .routing_reference
                        .as_deref()
                        .unwrap_or(&inv.deposit_address)
                        .to_string();

                    let invoice_id = u64::try_from(inv.id).unwrap_or(0);
                    let ttl = Duration::from_secs(remaining_secs);

                    if watchlist_engine
                        .register_watch_target(chain_id, lookup_key, invoice_id, ttl)
                        .is_ok()
                    {
                        hydrated_count = hydrated_count.saturating_add(1);
                    }
                }
            }
        }

        Ok(hydrated_count)
    }

    /// Inserts a newly generated checkout invoice into the SQLite ledger.
    pub fn insert_invoice(&self, record: &InvoiceRecord) -> Result<i64, DbError> {
        let table = Table::<InvoiceRecord>::new(self.conn.clone());
        table
            .insert(record)
            .unenvelope()
            .map_err(|e| DbError::Orm(format!("Failed to insert invoice: {e}")))
    }

    /// Queries an invoice by its internal integer primary key.
    pub fn find_invoice_by_id(&self, id: i64) -> Result<Option<InvoiceRecord>, DbError> {
        let table = Table::<InvoiceRecord>::new(self.conn.clone());
        match table.find(id).unenvelope() {
            Ok(inv) => Ok(inv),
            Err(e) => Err(DbError::Orm(format!("Failed to find invoice {id}: {e}"))),
        }
    }

    /// Inserts a new FIFO acquisition tax lot.
    pub fn insert_cost_basis_lot(&self, record: &CostBasisLotRecord) -> Result<i64, DbError> {
        let table = Table::<CostBasisLotRecord>::new(self.conn.clone());
        table
            .insert(record)
            .unenvelope()
            .map_err(|e| DbError::Orm(format!("Failed to insert cost basis lot: {e}")))
    }

    /// Records realized P&L resulting from asset disposal or treasury liquidation.
    pub fn insert_realized_pnl(&self, record: &RealizedPnlRecord) -> Result<i64, DbError> {
        let table = Table::<RealizedPnlRecord>::new(self.conn.clone());
        table
            .insert(record)
            .unenvelope()
            .map_err(|e| DbError::Orm(format!("Failed to insert realized PnL: {e}")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_auto_migration_and_crud() {
        let db = DatabaseManager::new(":memory:").expect("in-memory db");
        db.migrate_all().expect("migration should succeed");

        let inv = InvoiceRecord {
            id: 0,
            invoice_uuid: "inv_123456789".to_string(),
            chain_id: 1, // Ethereum
            logical_asset: "ETH".to_string(),
            deposit_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            routing_reference: None,
            expected_amount_raw: "50000000000000000".to_string(), // 0.05 ETH
            expected_amount_decimals: 18,
            locked_usd_micros: 125_000_000, // $125.00
            status: "PENDING".to_string(),
            detected_tx_hash: None,
            received_amount_raw: "0".to_string(),
            created_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_000_900,
            settled_at_unix: None,
        };

        let pk = db.insert_invoice(&inv).expect("insert should succeed");
        assert!(pk > 0);

        let retrieved = db.find_invoice_by_id(pk).expect("query should succeed");
        assert!(retrieved.is_some());
        let found = retrieved.unwrap();
        assert_eq!(found.invoice_uuid, "inv_123456789");
        assert_eq!(found.status, "PENDING");
    }

    #[test]
    fn test_cold_start_hydration_into_watchlist() {
        let db = DatabaseManager::new(":memory:").expect("in-memory db");
        db.migrate_all().expect("migration should succeed");

        let seed = [0xB3_u8; 64];
        let watchlist = InProcessWatchlistEngine::new(&seed, 10_000);

        let now_unix = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();

        // 1. Insert active pending invoice with future expiration
        let active_inv = InvoiceRecord {
            id: 0,
            invoice_uuid: "inv_active_001".to_string(),
            chain_id: 1, // Ethereum
            logical_asset: "USDT".to_string(),
            deposit_address: "0xabcdef1234567890abcdef1234567890abcdef12".to_string(),
            routing_reference: None,
            expected_amount_raw: "100000000".to_string(),
            expected_amount_decimals: 6,
            locked_usd_micros: 100_000_000,
            status: "PENDING".to_string(),
            detected_tx_hash: None,
            received_amount_raw: "0".to_string(),
            created_at_unix: now_unix,
            expires_at_unix: now_unix + 600, // 10 minutes remaining
            settled_at_unix: None,
        };
        let pk = db.insert_invoice(&active_inv).unwrap();

        // 2. Perform cold-start hydration
        let hydrated = db.hydrate_watchlist(&watchlist).expect("hydration succeeds");
        assert_eq!(hydrated, 1);

        // 3. Verify that watchlist immediately matches the address in O(1) time
        let matched = watchlist.match_watched_target(
            ChainId::EthereumMainnet,
            "0xabcdef1234567890abcdef1234567890abcdef12",
        );
        let pk_u64 = u64::try_from(pk).unwrap_or(0);
        assert_eq!(matched, Some(pk_u64));
    }
}
