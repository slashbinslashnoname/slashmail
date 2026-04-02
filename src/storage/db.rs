//! SQLite storage with FTS5 full-text search for messages.

use crate::error::AppError;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;
use uuid::Uuid;

/// A stored message with searchable text fields.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub id: Uuid,
    pub sender: String,
    pub recipient: String,
    pub subject: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub read: bool,
}

/// SQLite-backed message store with FTS5 full-text search.
pub struct MessageStore {
    conn: Connection,
}

impl MessageStore {
    /// Open (or create) the database at `path` and run migrations.
    pub fn open(path: &Path) -> Result<Self, AppError> {
        let conn = Connection::open(path)?;
        let store = Self::from_connection(conn)?;
        Ok(store)
    }

    /// Open an in-memory database (for tests).
    pub fn open_memory() -> Result<Self, AppError> {
        let conn = Connection::open_in_memory()?;
        let store = Self::from_connection(conn)?;
        Ok(store)
    }

    fn from_connection(conn: Connection) -> Result<Self, AppError> {
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        Self::assert_fts5(&conn)?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Assert that FTS5 is available in this SQLite build.
    fn assert_fts5(conn: &Connection) -> Result<(), AppError> {
        let mut stmt = conn.prepare("PRAGMA compile_options")?;
        let options: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        if !options.iter().any(|opt| opt == "ENABLE_FTS5") {
            return Err(AppError::Other(
                "SQLite was not compiled with FTS5 support".to_string(),
            ));
        }
        Ok(())
    }

    /// Run schema migrations: messages table, FTS5 virtual table, and triggers.
    fn migrate(&self) -> Result<(), AppError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                id          TEXT PRIMARY KEY,
                sender      TEXT NOT NULL,
                recipient   TEXT NOT NULL,
                subject     TEXT NOT NULL DEFAULT '',
                body        TEXT NOT NULL DEFAULT '',
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                read        INTEGER NOT NULL DEFAULT 0
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                sender,
                recipient,
                subject,
                body,
                content='messages',
                content_rowid='rowid'
            );

            -- Triggers to keep FTS index in sync with messages table.
            CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
                INSERT INTO messages_fts(rowid, sender, recipient, subject, body)
                VALUES (new.rowid, new.sender, new.recipient, new.subject, new.body);
            END;

            CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
                INSERT INTO messages_fts(messages_fts, rowid, sender, recipient, subject, body)
                VALUES ('delete', old.rowid, old.sender, old.recipient, old.subject, old.body);
            END;

            CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
                INSERT INTO messages_fts(messages_fts, rowid, sender, recipient, subject, body)
                VALUES ('delete', old.rowid, old.sender, old.recipient, old.subject, old.body);
                INSERT INTO messages_fts(rowid, sender, recipient, subject, body)
                VALUES (new.rowid, new.sender, new.recipient, new.subject, new.body);
            END;",
        )?;
        Ok(())
    }

    /// Insert a message into the store.
    pub fn insert_message(&self, msg: &Message) -> Result<(), AppError> {
        self.conn.execute(
            "INSERT INTO messages (id, sender, recipient, subject, body, created_at, read)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                msg.id.to_string(),
                msg.sender,
                msg.recipient,
                msg.subject,
                msg.body,
                msg.created_at.to_rfc3339(),
                msg.read as i32,
            ],
        )?;
        Ok(())
    }

    /// List messages ordered by creation time (newest first).
    /// Pass `limit = 0` for no limit.
    pub fn list_messages(&self, limit: u32) -> Result<Vec<Message>, AppError> {
        let sql = if limit > 0 {
            format!(
                "SELECT id, sender, recipient, subject, body, created_at, read
                 FROM messages ORDER BY created_at DESC LIMIT {}",
                limit
            )
        } else {
            "SELECT id, sender, recipient, subject, body, created_at, read
             FROM messages ORDER BY created_at DESC"
                .to_string()
        };

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_message)?;
        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    /// Full-text search across sender, recipient, subject, and body.
    /// Uses FTS5 match syntax.
    pub fn search_messages(&self, query: &str) -> Result<Vec<Message>, AppError> {
        let mut stmt = self.conn.prepare(
            "SELECT m.id, m.sender, m.recipient, m.subject, m.body, m.created_at, m.read
             FROM messages m
             JOIN messages_fts fts ON m.rowid = fts.rowid
             WHERE messages_fts MATCH ?1
             ORDER BY fts.rank",
        )?;
        let rows = stmt.query_map(params![query], row_to_message)?;
        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    /// Access the raw connection.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

fn row_to_message(row: &rusqlite::Row) -> rusqlite::Result<Message> {
    let id_str: String = row.get(0)?;
    let created_str: String = row.get(5)?;
    let read_int: i32 = row.get(6)?;

    let id = Uuid::parse_str(&id_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;
    let created_at = DateTime::parse_from_rfc3339(&created_str)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            // Fall back to SQLite datetime format "YYYY-MM-DD HH:MM:SS"
            chrono::NaiveDateTime::parse_from_str(&created_str, "%Y-%m-%d %H:%M:%S")
                .map(|ndt| ndt.and_utc())
        })
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e)))?;

    Ok(Message {
        id,
        sender: row.get(1)?,
        recipient: row.get(2)?,
        subject: row.get(3)?,
        body: row.get(4)?,
        created_at,
        read: read_int != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_message(sender: &str, recipient: &str, subject: &str, body: &str) -> Message {
        Message {
            id: Uuid::new_v4(),
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
            created_at: Utc::now(),
            read: false,
        }
    }

    #[test]
    fn fts5_is_available() {
        // If this fails, rusqlite bundled build doesn't include FTS5
        MessageStore::open_memory().unwrap();
    }

    #[test]
    fn migrate_is_idempotent() {
        let store = MessageStore::open_memory().unwrap();
        // migrate runs in open_memory; calling again should not error
        store.migrate().unwrap();
    }

    #[test]
    fn insert_and_list_messages() {
        let store = MessageStore::open_memory().unwrap();

        let m1 = make_message("alice", "bob", "Hello", "Hi Bob, how are you?");
        let m2 = make_message("bob", "alice", "Re: Hello", "I'm fine, thanks!");

        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();

        let all = store.list_messages(0).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn list_messages_respects_limit() {
        let store = MessageStore::open_memory().unwrap();

        for i in 0..5 {
            let m = make_message("alice", "bob", &format!("Msg {}", i), "body");
            store.insert_message(&m).unwrap();
        }

        let limited = store.list_messages(3).unwrap();
        assert_eq!(limited.len(), 3);
    }

    #[test]
    fn search_messages_finds_by_body() {
        let store = MessageStore::open_memory().unwrap();

        let m1 = make_message("alice", "bob", "Greetings", "Let's meet for coffee tomorrow");
        let m2 = make_message("carol", "bob", "Report", "Q3 quarterly earnings report");
        let m3 = make_message("dave", "bob", "Lunch", "Want to grab coffee at noon?");

        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();
        store.insert_message(&m3).unwrap();

        let results = store.search_messages("coffee").unwrap();
        assert_eq!(results.len(), 2);

        let senders: Vec<&str> = results.iter().map(|m| m.sender.as_str()).collect();
        assert!(senders.contains(&"alice"));
        assert!(senders.contains(&"dave"));
    }

    #[test]
    fn search_messages_finds_by_subject() {
        let store = MessageStore::open_memory().unwrap();

        let m1 = make_message("alice", "bob", "Important meeting", "See you there");
        let m2 = make_message("carol", "bob", "Casual chat", "Nothing important");

        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();

        let results = store.search_messages("subject:meeting").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sender, "alice");
    }

    #[test]
    fn search_messages_finds_by_sender() {
        let store = MessageStore::open_memory().unwrap();

        let m1 = make_message("alice", "bob", "Hi", "Hello");
        let m2 = make_message("carol", "bob", "Hi", "Hello");

        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();

        let results = store.search_messages("sender:alice").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sender, "alice");
    }

    #[test]
    fn search_returns_empty_for_no_match() {
        let store = MessageStore::open_memory().unwrap();

        let m1 = make_message("alice", "bob", "Hello", "World");
        store.insert_message(&m1).unwrap();

        let results = store.search_messages("xyznonexistent").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn insert_preserves_fields() {
        let store = MessageStore::open_memory().unwrap();

        let msg = Message {
            id: Uuid::new_v4(),
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            subject: "Test Subject".to_string(),
            body: "Test Body".to_string(),
            created_at: Utc::now(),
            read: true,
        };

        store.insert_message(&msg).unwrap();

        let all = store.list_messages(0).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, msg.id);
        assert_eq!(all[0].sender, "alice");
        assert_eq!(all[0].recipient, "bob");
        assert_eq!(all[0].subject, "Test Subject");
        assert_eq!(all[0].body, "Test Body");
        assert_eq!(all[0].created_at, msg.created_at);
        assert!(all[0].read);
    }

    #[test]
    fn fts_syncs_on_delete() {
        let store = MessageStore::open_memory().unwrap();

        let m = make_message("alice", "bob", "Delete me", "unique_keyword_xyz");
        store.insert_message(&m).unwrap();

        // Verify searchable
        let results = store.search_messages("unique_keyword_xyz").unwrap();
        assert_eq!(results.len(), 1);

        // Delete
        store
            .conn()
            .execute("DELETE FROM messages WHERE id = ?1", params![m.id.to_string()])
            .unwrap();

        // FTS should no longer find it
        let results = store.search_messages("unique_keyword_xyz").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn open_file_based_store() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("test.db");

        let store = MessageStore::open(&db_path).unwrap();
        let m = make_message("alice", "bob", "Hi", "Persistent message");
        store.insert_message(&m).unwrap();
        drop(store);

        // Reopen and verify data persists
        let store2 = MessageStore::open(&db_path).unwrap();
        let all = store2.list_messages(0).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].body, "Persistent message");
    }
}
