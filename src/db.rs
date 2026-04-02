//! SQLite storage via rusqlite.

use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) the database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        Ok(Self { conn })
    }

    /// Open an in-memory database (useful for tests).
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        Ok(Self { conn })
    }

    /// Run schema migrations.
    pub fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                id          TEXT PRIMARY KEY,
                sender      TEXT NOT NULL,
                recipient   TEXT NOT NULL,
                body        BLOB NOT NULL,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                read        INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS identities (
                public_key  TEXT PRIMARY KEY,
                alias       TEXT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;
        Ok(())
    }

    /// Access the raw connection (for advanced queries).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_memory_and_migrate() {
        let store = Store::open_memory().unwrap();
        store.migrate().unwrap();
        // Verify tables exist
        let count: i64 = store
            .conn()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('messages','identities')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn migrate_is_idempotent() {
        let store = Store::open_memory().unwrap();
        store.migrate().unwrap();
        store.migrate().unwrap(); // should not error
    }
}
