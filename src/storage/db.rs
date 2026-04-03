//! SQLite storage with FTS5 full-text search for messages.

use crate::error::AppError;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;
use uuid::Uuid;

/// Current schema version.
const SCHEMA_VERSION: i64 = 1;

/// A stored message with searchable text fields.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub id: Uuid,
    pub swarm_id: String,
    pub folder_path: String,
    pub sender_pubkey: [u8; 32],
    pub sender: String,
    pub recipient: String,
    pub subject: String,
    pub body: String,
    pub tags: String,
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

    /// Return the current schema version (0 if no migrations have run).
    pub fn schema_version(&self) -> Result<i64, AppError> {
        // db_migrations table may not exist yet.
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='db_migrations')",
            [],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(0);
        }
        let version: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM db_migrations",
            [],
            |row| row.get(0),
        )?;
        Ok(version)
    }

    /// Run schema migrations up to SCHEMA_VERSION.
    fn migrate(&self) -> Result<(), AppError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS db_migrations (
                version    INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;

        let current = self.schema_version()?;

        if current < 1 {
            self.migrate_v1()?;
        }

        Ok(())
    }

    /// V1: messages, message_tags, FTS5 with tags column, sync triggers.
    fn migrate_v1(&self) -> Result<(), AppError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                id             TEXT PRIMARY KEY,
                swarm_id       TEXT NOT NULL DEFAULT '',
                folder_path    TEXT NOT NULL DEFAULT 'INBOX',
                sender_pubkey  BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000',
                sender         TEXT NOT NULL,
                recipient      TEXT NOT NULL,
                subject        TEXT NOT NULL DEFAULT '',
                body           TEXT NOT NULL DEFAULT '',
                tags           TEXT NOT NULL DEFAULT '',
                created_at     TEXT NOT NULL DEFAULT (datetime('now')),
                read           INTEGER NOT NULL DEFAULT 0
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                sender,
                recipient,
                subject,
                body,
                tags,
                content='messages',
                content_rowid='rowid'
            );

            -- Triggers to keep FTS index in sync with messages table.
            CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
                INSERT INTO messages_fts(rowid, sender, recipient, subject, body, tags)
                VALUES (new.rowid, new.sender, new.recipient, new.subject, new.body, new.tags);
            END;

            CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
                INSERT INTO messages_fts(messages_fts, rowid, sender, recipient, subject, body, tags)
                VALUES ('delete', old.rowid, old.sender, old.recipient, old.subject, old.body, old.tags);
            END;

            CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
                INSERT INTO messages_fts(messages_fts, rowid, sender, recipient, subject, body, tags)
                VALUES ('delete', old.rowid, old.sender, old.recipient, old.subject, old.body, old.tags);
                INSERT INTO messages_fts(rowid, sender, recipient, subject, body, tags)
                VALUES (new.rowid, new.sender, new.recipient, new.subject, new.body, new.tags);
            END;

            CREATE TABLE IF NOT EXISTS message_tags (
                envelope_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                tag         TEXT NOT NULL,
                PRIMARY KEY (envelope_id, tag)
            );

            CREATE INDEX IF NOT EXISTS idx_message_tags_tag ON message_tags(tag);

            INSERT INTO db_migrations (version) VALUES (1);",
        )?;
        Ok(())
    }

    /// Insert a message into the store.
    pub fn insert_message(&self, msg: &Message) -> Result<(), AppError> {
        self.conn.execute(
            "INSERT INTO messages (id, swarm_id, folder_path, sender_pubkey, sender, recipient, subject, body, tags, created_at, read)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                msg.id.to_string(),
                msg.swarm_id,
                msg.folder_path,
                msg.sender_pubkey.as_slice(),
                msg.sender,
                msg.recipient,
                msg.subject,
                msg.body,
                msg.tags,
                msg.created_at.to_rfc3339(),
                msg.read as i32,
            ],
        )?;
        Ok(())
    }

    /// List messages ordered by creation time (newest first).
    /// Pass `limit = 0` for no limit.
    pub fn list_messages(&self, limit: u32) -> Result<Vec<Message>, AppError> {
        let limit_val: i64 = if limit > 0 { limit as i64 } else { -1 };
        let mut stmt = self.conn.prepare(
            "SELECT id, swarm_id, folder_path, sender_pubkey, sender, recipient, subject, body, tags, created_at, read
             FROM messages ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit_val], row_to_message)?;
        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    /// Full-text search across sender, recipient, subject, body, and tags.
    /// Uses FTS5 match syntax.
    pub fn search_messages(&self, query: &str) -> Result<Vec<Message>, AppError> {
        let mut stmt = self.conn.prepare(
            "SELECT m.id, m.swarm_id, m.folder_path, m.sender_pubkey, m.sender, m.recipient, m.subject, m.body, m.tags, m.created_at, m.read
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

    /// Flush the WAL to the main database file via a full checkpoint.
    ///
    /// Should be called during graceful shutdown to ensure all writes are
    /// persisted to the main database file.
    pub fn flush_wal(&self) -> Result<(), AppError> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(FULL)")?;
        Ok(())
    }

    /// Access the raw connection.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Add a tag to a message. Does nothing if the tag already exists.
    pub fn tag_message(&self, envelope_id: &Uuid, tag: &str) -> Result<(), AppError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO message_tags (envelope_id, tag) VALUES (?1, ?2)",
            params![envelope_id.to_string(), tag],
        )?;
        self.refresh_tags_text(envelope_id)?;
        Ok(())
    }

    /// Idempotently set the full set of tags for a message.
    /// Inserts missing tags and removes tags not in the provided list.
    pub fn upsert_tags(&self, envelope_id: &Uuid, tags: &[&str]) -> Result<(), AppError> {
        let id_str = envelope_id.to_string();
        // Insert any new tags (idempotent via INSERT OR IGNORE).
        for tag in tags {
            self.conn.execute(
                "INSERT OR IGNORE INTO message_tags (envelope_id, tag) VALUES (?1, ?2)",
                params![id_str, *tag],
            )?;
        }
        // Remove tags not in the provided list.
        if tags.is_empty() {
            self.conn.execute(
                "DELETE FROM message_tags WHERE envelope_id = ?1",
                params![id_str],
            )?;
        } else {
            // Build a comma-separated placeholder list for the IN clause.
            let placeholders: Vec<String> = (0..tags.len()).map(|i| format!("?{}", i + 2)).collect();
            let sql = format!(
                "DELETE FROM message_tags WHERE envelope_id = ?1 AND tag NOT IN ({})",
                placeholders.join(", ")
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let mut param_idx = 1;
            stmt.raw_bind_parameter(param_idx, &id_str)?;
            for tag in tags {
                param_idx += 1;
                stmt.raw_bind_parameter(param_idx, *tag)?;
            }
            stmt.raw_execute()?;
        }
        self.refresh_tags_text(envelope_id)?;
        Ok(())
    }

    /// Remove a tag from a message.
    pub fn untag_message(&self, envelope_id: &Uuid, tag: &str) -> Result<(), AppError> {
        self.conn.execute(
            "DELETE FROM message_tags WHERE envelope_id = ?1 AND tag = ?2",
            params![envelope_id.to_string(), tag],
        )?;
        self.refresh_tags_text(envelope_id)?;
        Ok(())
    }

    /// Get all tags for a given message.
    pub fn get_message_tags(&self, envelope_id: &Uuid) -> Result<Vec<String>, AppError> {
        let mut stmt = self
            .conn
            .prepare("SELECT tag FROM message_tags WHERE envelope_id = ?1 ORDER BY tag")?;
        let rows = stmt.query_map(params![envelope_id.to_string()], |row| row.get(0))?;
        let mut tags = Vec::new();
        for row in rows {
            tags.push(row?);
        }
        Ok(tags)
    }

    /// Get all messages with a given tag, ordered by creation time (newest first).
    pub fn messages_by_tag(&self, tag: &str) -> Result<Vec<Message>, AppError> {
        let mut stmt = self.conn.prepare(
            "SELECT m.id, m.swarm_id, m.folder_path, m.sender_pubkey, m.sender, m.recipient, m.subject, m.body, m.tags, m.created_at, m.read
             FROM messages m
             JOIN message_tags mt ON m.id = mt.envelope_id
             WHERE mt.tag = ?1
             ORDER BY m.created_at DESC",
        )?;
        let rows = stmt.query_map(params![tag], row_to_message)?;
        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    /// Refresh the denormalized tags column in messages from message_tags.
    fn refresh_tags_text(&self, envelope_id: &Uuid) -> Result<(), AppError> {
        self.conn.execute(
            "UPDATE messages SET tags = (
                SELECT COALESCE(GROUP_CONCAT(tag, ' '), '')
                FROM message_tags WHERE envelope_id = ?1
            ) WHERE id = ?1",
            params![envelope_id.to_string()],
        )?;
        Ok(())
    }
}

fn row_to_message(row: &rusqlite::Row) -> rusqlite::Result<Message> {
    // Column order: id(0), swarm_id(1), folder_path(2), sender_pubkey(3),
    //   sender(4), recipient(5), subject(6), body(7), tags(8), created_at(9), read(10)
    let id_str: String = row.get(0)?;
    let swarm_id: String = row.get(1)?;
    let folder_path: String = row.get(2)?;
    let pubkey_blob: Vec<u8> = row.get(3)?;
    let tags: String = row.get(8)?;
    let created_str: String = row.get(9)?;
    let read_int: i32 = row.get(10)?;

    let id = Uuid::parse_str(&id_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;

    let sender_pubkey: [u8; 32] = pubkey_blob.try_into().map_err(|v: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("sender_pubkey has {} bytes, expected 32", v.len()),
            )),
        )
    })?;

    let created_at = DateTime::parse_from_rfc3339(&created_str)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            // Fall back to SQLite datetime format "YYYY-MM-DD HH:MM:SS"
            chrono::NaiveDateTime::parse_from_str(&created_str, "%Y-%m-%d %H:%M:%S")
                .map(|ndt| ndt.and_utc())
        })
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e)))?;

    Ok(Message {
        id,
        swarm_id,
        folder_path,
        sender_pubkey,
        sender: row.get(4)?,
        recipient: row.get(5)?,
        subject: row.get(6)?,
        body: row.get(7)?,
        tags,
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
            swarm_id: "test-swarm".to_string(),
            folder_path: "INBOX".to_string(),
            sender_pubkey: [0xAA; 32],
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
            tags: String::new(),
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
            swarm_id: "pub_general".to_string(),
            folder_path: "INBOX/work".to_string(),
            sender_pubkey: [0xBB; 32],
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            subject: "Test Subject".to_string(),
            body: "Test Body".to_string(),
            tags: String::new(),
            created_at: Utc::now(),
            read: true,
        };

        store.insert_message(&msg).unwrap();

        let all = store.list_messages(0).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, msg.id);
        assert_eq!(all[0].swarm_id, "pub_general");
        assert_eq!(all[0].folder_path, "INBOX/work");
        assert_eq!(all[0].sender_pubkey, [0xBB; 32]);
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
    fn flush_wal_succeeds() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();
        // WAL checkpoint should succeed (no-op on in-memory, but must not error).
        store.flush_wal().unwrap();
    }

    #[test]
    fn flush_wal_on_file_based_store() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("wal_test.db");

        let store = MessageStore::open(&db_path).unwrap();
        let m = make_message("alice", "bob", "Hi", "WAL flush test");
        store.insert_message(&m).unwrap();

        store.flush_wal().unwrap();

        // Data should be readable after flush.
        let all = store.list_messages(0).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].body, "WAL flush test");
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
        assert_eq!(all[0].swarm_id, "test-swarm");
        assert_eq!(all[0].folder_path, "INBOX");
        assert_eq!(all[0].sender_pubkey, [0xAA; 32]);
    }

    #[test]
    fn new_columns_roundtrip_distinct_values() {
        let store = MessageStore::open_memory().unwrap();

        let mut m1 = make_message("alice", "bob", "Hi", "Hello");
        m1.swarm_id = "pub_general".to_string();
        m1.folder_path = "INBOX/priority".to_string();
        m1.sender_pubkey = [0x01; 32];

        let mut m2 = make_message("carol", "dave", "Re", "World");
        m2.swarm_id = "prv_alice_bob".to_string();
        m2.folder_path = "Sent".to_string();
        m2.sender_pubkey = [0x02; 32];

        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();

        let all = store.list_messages(0).unwrap();
        assert_eq!(all.len(), 2);

        // Newest first
        assert_eq!(all[0].swarm_id, "prv_alice_bob");
        assert_eq!(all[0].folder_path, "Sent");
        assert_eq!(all[0].sender_pubkey, [0x02; 32]);

        assert_eq!(all[1].swarm_id, "pub_general");
        assert_eq!(all[1].folder_path, "INBOX/priority");
        assert_eq!(all[1].sender_pubkey, [0x01; 32]);
    }

    #[test]
    fn tag_message_and_get_tags() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();

        store.tag_message(&m.id, "inbox").unwrap();
        store.tag_message(&m.id, "important").unwrap();

        let tags = store.get_message_tags(&m.id).unwrap();
        assert_eq!(tags, vec!["important", "inbox"]); // sorted alphabetically
    }

    #[test]
    fn tag_message_is_idempotent() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();

        store.tag_message(&m.id, "inbox").unwrap();
        store.tag_message(&m.id, "inbox").unwrap(); // duplicate, should not error

        let tags = store.get_message_tags(&m.id).unwrap();
        assert_eq!(tags, vec!["inbox"]);
    }

    #[test]
    fn untag_message_removes_tag() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();

        store.tag_message(&m.id, "inbox").unwrap();
        store.tag_message(&m.id, "important").unwrap();
        store.untag_message(&m.id, "inbox").unwrap();

        let tags = store.get_message_tags(&m.id).unwrap();
        assert_eq!(tags, vec!["important"]);
    }

    #[test]
    fn get_messages_by_tag() {
        let store = MessageStore::open_memory().unwrap();

        let m1 = make_message("alice", "bob", "Hi", "Hello");
        let m2 = make_message("carol", "bob", "Hey", "World");
        let m3 = make_message("dave", "bob", "Yo", "Sup");
        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();
        store.insert_message(&m3).unwrap();

        store.tag_message(&m1.id, "important").unwrap();
        store.tag_message(&m2.id, "important").unwrap();
        store.tag_message(&m3.id, "spam").unwrap();

        let important = store.messages_by_tag("important").unwrap();
        assert_eq!(important.len(), 2);
        let senders: Vec<&str> = important.iter().map(|m| m.sender.as_str()).collect();
        assert!(senders.contains(&"alice"));
        assert!(senders.contains(&"carol"));

        let spam = store.messages_by_tag("spam").unwrap();
        assert_eq!(spam.len(), 1);
        assert_eq!(spam[0].sender, "dave");
    }

    #[test]
    fn messages_by_tag_returns_empty_for_unknown_tag() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();
        store.tag_message(&m.id, "inbox").unwrap();

        let results = store.messages_by_tag("nonexistent").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn tags_cascade_on_message_delete() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();
        store.tag_message(&m.id, "inbox").unwrap();

        store
            .conn()
            .execute("DELETE FROM messages WHERE id = ?1", params![m.id.to_string()])
            .unwrap();

        let tags = store.get_message_tags(&m.id).unwrap();
        assert!(tags.is_empty());

        let by_tag = store.messages_by_tag("inbox").unwrap();
        assert!(by_tag.is_empty());
    }

    #[test]
    fn get_message_tags_empty_for_untagged() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();

        let tags = store.get_message_tags(&m.id).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn untag_message_nonexistent_is_noop() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();

        // Removing a tag that was never applied should not error.
        store.untag_message(&m.id, "inbox").unwrap();
        let tags = store.get_message_tags(&m.id).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn search_returns_new_columns() {
        let store = MessageStore::open_memory().unwrap();

        let mut m = make_message("alice", "bob", "Searchable", "unique_search_term_abc");
        m.swarm_id = "pub_room".to_string();
        m.folder_path = "Archive".to_string();
        m.sender_pubkey = [0xCC; 32];

        store.insert_message(&m).unwrap();

        let results = store.search_messages("unique_search_term_abc").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].swarm_id, "pub_room");
        assert_eq!(results[0].folder_path, "Archive");
        assert_eq!(results[0].sender_pubkey, [0xCC; 32]);
    }

    #[test]
    fn schema_version_tracks_migrations() {
        let store = MessageStore::open_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);

        // db_migrations table has exactly one row
        let count: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM db_migrations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn migrate_is_idempotent_with_versioning() {
        let store = MessageStore::open_memory().unwrap();
        // Running migrate again should not error or duplicate rows.
        store.migrate().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);

        let count: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM db_migrations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn upsert_tags_sets_tags() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();

        store.upsert_tags(&m.id, &["inbox", "important"]).unwrap();
        let tags = store.get_message_tags(&m.id).unwrap();
        assert_eq!(tags, vec!["important", "inbox"]);
    }

    #[test]
    fn upsert_tags_is_idempotent() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();

        store.upsert_tags(&m.id, &["inbox", "important"]).unwrap();
        store.upsert_tags(&m.id, &["inbox", "important"]).unwrap();
        let tags = store.get_message_tags(&m.id).unwrap();
        assert_eq!(tags, vec!["important", "inbox"]);
    }

    #[test]
    fn upsert_tags_removes_old_tags() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();

        store.upsert_tags(&m.id, &["inbox", "important", "urgent"]).unwrap();
        store.upsert_tags(&m.id, &["inbox"]).unwrap();
        let tags = store.get_message_tags(&m.id).unwrap();
        assert_eq!(tags, vec!["inbox"]);
    }

    #[test]
    fn upsert_tags_empty_clears_all() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();

        store.upsert_tags(&m.id, &["inbox", "important"]).unwrap();
        store.upsert_tags(&m.id, &[]).unwrap();
        let tags = store.get_message_tags(&m.id).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn upsert_tags_syncs_denormalized_tags_text() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();

        store.upsert_tags(&m.id, &["inbox", "important"]).unwrap();

        let all = store.list_messages(0).unwrap();
        // tags_text is space-separated, order determined by GROUP_CONCAT
        let tags_words: Vec<&str> = all[0].tags.split_whitespace().collect();
        assert!(tags_words.contains(&"inbox"));
        assert!(tags_words.contains(&"important"));
    }

    #[test]
    fn fts5_searches_tags() {
        let store = MessageStore::open_memory().unwrap();
        let m1 = make_message("alice", "bob", "Hi", "Hello world");
        let m2 = make_message("carol", "bob", "Hey", "Goodbye world");
        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();

        store.upsert_tags(&m1.id, &["urgent"]).unwrap();

        let results = store.search_messages("tags:urgent").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sender, "alice");
    }

    // ── Additional storage tests (slashmail-hwt.2) ──────────────────────

    #[test]
    fn upsert_tags_idempotent_preserves_fts_consistency() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Tagged", "Body text");
        store.insert_message(&m).unwrap();

        // Apply same tags three times
        for _ in 0..3 {
            store.upsert_tags(&m.id, &["inbox", "priority"]).unwrap();
        }

        // Normalized tags are correct
        let tags = store.get_message_tags(&m.id).unwrap();
        assert_eq!(tags, vec!["inbox", "priority"]);

        // Denormalized text is consistent
        let all = store.list_messages(0).unwrap();
        let words: Vec<&str> = all[0].tags.split_whitespace().collect();
        assert_eq!(words.len(), 2);
        assert!(words.contains(&"inbox"));
        assert!(words.contains(&"priority"));

        // FTS index still finds by each tag
        assert_eq!(store.search_messages("tags:inbox").unwrap().len(), 1);
        assert_eq!(store.search_messages("tags:priority").unwrap().len(), 1);
    }

    #[test]
    fn upsert_tags_idempotent_no_duplicate_rows() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Body");
        store.insert_message(&m).unwrap();

        store.upsert_tags(&m.id, &["a", "b"]).unwrap();
        store.upsert_tags(&m.id, &["a", "b"]).unwrap();

        let count: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM message_tags WHERE envelope_id = ?1",
                params![m.id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn messages_by_tag_returns_newest_first() {
        let store = MessageStore::open_memory().unwrap();

        let mut m1 = make_message("alice", "bob", "Old", "First");
        m1.created_at = DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut m2 = make_message("carol", "bob", "New", "Second");
        m2.created_at = DateTime::parse_from_rfc3339("2024-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();

        store.tag_message(&m1.id, "work").unwrap();
        store.tag_message(&m2.id, "work").unwrap();

        let results = store.messages_by_tag("work").unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].sender, "carol"); // newest first
        assert_eq!(results[1].sender, "alice");
    }

    #[test]
    fn messages_by_tag_preserves_all_fields() {
        let store = MessageStore::open_memory().unwrap();

        let mut m = make_message("alice", "bob", "Subject", "Body");
        m.swarm_id = "my-swarm".to_string();
        m.folder_path = "Archive".to_string();
        m.sender_pubkey = [0xDD; 32];
        m.read = true;

        store.insert_message(&m).unwrap();
        store.tag_message(&m.id, "test-tag").unwrap();

        let results = store.messages_by_tag("test-tag").unwrap();
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.id, m.id);
        assert_eq!(r.swarm_id, "my-swarm");
        assert_eq!(r.folder_path, "Archive");
        assert_eq!(r.sender_pubkey, [0xDD; 32]);
        assert_eq!(r.sender, "alice");
        assert_eq!(r.recipient, "bob");
        assert_eq!(r.subject, "Subject");
        assert_eq!(r.body, "Body");
        assert!(r.read);
    }

    #[test]
    fn fts5_search_returns_tags_in_results() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "searchterm_unique_789");
        store.insert_message(&m).unwrap();

        store
            .upsert_tags(&m.id, &["important", "urgent"])
            .unwrap();

        // Search by body, verify tags column is populated in result
        let results = store.search_messages("searchterm_unique_789").unwrap();
        assert_eq!(results.len(), 1);
        let tags_words: Vec<&str> = results[0].tags.split_whitespace().collect();
        assert!(tags_words.contains(&"important"));
        assert!(tags_words.contains(&"urgent"));
    }

    #[test]
    fn fts5_search_by_tag_returns_tags_column() {
        let store = MessageStore::open_memory().unwrap();
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();

        store
            .upsert_tags(&m.id, &["confidential", "reviewed"])
            .unwrap();

        let results = store.search_messages("tags:confidential").unwrap();
        assert_eq!(results.len(), 1);
        let tags_words: Vec<&str> = results[0].tags.split_whitespace().collect();
        assert!(tags_words.contains(&"confidential"));
        assert!(tags_words.contains(&"reviewed"));
    }

    #[test]
    fn migration_v1_from_empty_database() {
        // Simulate opening a fresh database — verify v1 schema is applied
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .unwrap();
        MessageStore::assert_fts5(&conn).unwrap();
        let store = MessageStore { conn };
        assert_eq!(store.schema_version().unwrap(), 0);

        store.migrate().unwrap();
        assert_eq!(store.schema_version().unwrap(), 1);

        // Verify tables exist and work
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();
        store.upsert_tags(&m.id, &["inbox"]).unwrap();

        let results = store.messages_by_tag("inbox").unwrap();
        assert_eq!(results.len(), 1);

        let fts = store.search_messages("tags:inbox").unwrap();
        assert_eq!(fts.len(), 1);
    }

    #[test]
    fn migration_v1_is_idempotent_with_existing_data() {
        let store = MessageStore::open_memory().unwrap();

        // Insert data
        let m = make_message("alice", "bob", "Hi", "Hello");
        store.insert_message(&m).unwrap();
        store.upsert_tags(&m.id, &["inbox", "important"]).unwrap();

        // Re-run migration — should not error or lose data
        store.migrate().unwrap();
        assert_eq!(store.schema_version().unwrap(), 1);

        let tags = store.get_message_tags(&m.id).unwrap();
        assert_eq!(tags, vec!["important", "inbox"]);

        let all = store.list_messages(0).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].sender, "alice");
    }

    #[test]
    fn migration_v1_file_based_upgrade_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("upgrade_test.db");

        // Create v1 database, insert data, close
        {
            let store = MessageStore::open(&db_path).unwrap();
            let m = make_message("alice", "bob", "Hi", "Persistent");
            store.insert_message(&m).unwrap();
            store.upsert_tags(&m.id, &["saved"]).unwrap();
            store.flush_wal().unwrap();
        }

        // Reopen — migrate runs again, data survives
        {
            let store = MessageStore::open(&db_path).unwrap();
            assert_eq!(store.schema_version().unwrap(), 1);

            let all = store.list_messages(0).unwrap();
            assert_eq!(all.len(), 1);
            assert_eq!(all[0].body, "Persistent");

            let results = store.messages_by_tag("saved").unwrap();
            assert_eq!(results.len(), 1);

            let fts = store.search_messages("tags:saved").unwrap();
            assert_eq!(fts.len(), 1);
        }
    }
}
