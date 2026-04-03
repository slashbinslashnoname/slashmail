use clap::Parser;

use super::{message_rows, truncate_chars, Args, Command};
use crate::storage::db::Message;
use chrono::Utc;
use uuid::Uuid;

/// Helper to parse CLI args from a slice of strings.
fn parse(args: &[&str]) -> Args {
    Args::try_parse_from(args).expect("failed to parse args")
}

#[test]
fn parse_init() {
    let args = parse(&["slashmail", "init"]);
    assert!(matches!(args.command, Command::Init));
}

#[test]
fn parse_status() {
    let args = parse(&["slashmail", "status"]);
    assert!(matches!(args.command, Command::Status));
}

#[test]
fn parse_send_with_to_and_tags() {
    let args = parse(&["slashmail", "send", "--to", "AAAA", "--tags", "inbox,urgent"]);
    match args.command {
        Command::Send { to, tags } => {
            assert_eq!(to, "AAAA");
            assert_eq!(tags, vec!["inbox", "urgent"]);
        }
        _ => panic!("expected Send"),
    }
}

#[test]
fn parse_send_no_tags() {
    let args = parse(&["slashmail", "send", "--to", "BBBB"]);
    match args.command {
        Command::Send { to, tags } => {
            assert_eq!(to, "BBBB");
            assert!(tags.is_empty());
        }
        _ => panic!("expected Send"),
    }
}

#[test]
fn parse_list_no_tag() {
    let args = parse(&["slashmail", "list"]);
    match args.command {
        Command::List { tag } => assert!(tag.is_none()),
        _ => panic!("expected List"),
    }
}

#[test]
fn parse_list_with_tag() {
    let args = parse(&["slashmail", "list", "--tag", "inbox"]);
    match args.command {
        Command::List { tag } => assert_eq!(tag.as_deref(), Some("inbox")),
        _ => panic!("expected List"),
    }
}

#[test]
fn parse_search() {
    let args = parse(&["slashmail", "search", "hello world"]);
    match args.command {
        Command::Search { query } => assert_eq!(query, "hello world"),
        _ => panic!("expected Search"),
    }
}

#[test]
fn parse_add_peer() {
    let args = parse(&["slashmail", "add-peer", "/ip4/1.2.3.4/tcp/4001"]);
    match args.command {
        Command::AddPeer { addr } => assert_eq!(addr, "/ip4/1.2.3.4/tcp/4001"),
        _ => panic!("expected AddPeer"),
    }
}

#[test]
fn parse_peers() {
    let args = parse(&["slashmail", "peers"]);
    assert!(matches!(args.command, Command::Peers));
}

#[test]
fn parse_daemon_default_listen() {
    let args = parse(&["slashmail", "daemon"]);
    match args.command {
        Command::Daemon { listen } => assert_eq!(listen, "/ip4/0.0.0.0/tcp/0"),
        _ => panic!("expected Daemon"),
    }
}

#[test]
fn whoami_is_not_a_command() {
    let result = Args::try_parse_from(&["slashmail", "whoami"]);
    assert!(result.is_err(), "whoami should no longer be a valid subcommand");
}

#[test]
fn inbox_is_not_a_command() {
    let result = Args::try_parse_from(&["slashmail", "inbox"]);
    assert!(result.is_err(), "inbox should no longer be a valid subcommand");
}

/// Helper to create a test message with sensible defaults.
fn test_message(sender: &str, subject: &str, body: &str, tags: &str) -> Message {
    Message {
        id: Uuid::new_v4(),
        swarm_id: "test-swarm".into(),
        folder_path: "inbox".into(),
        sender_pubkey: [0u8; 32],
        sender: sender.into(),
        recipient: "bob".into(),
        subject: subject.into(),
        body: body.into(),
        tags: tags.into(),
        created_at: Utc::now(),
        read: false,
    }
}

#[test]
fn truncate_chars_ascii_no_truncation() {
    assert_eq!(truncate_chars("hello", 10), "hello");
}

#[test]
fn truncate_chars_ascii_truncates() {
    assert_eq!(truncate_chars("hello world", 5), "hello…");
}

#[test]
fn truncate_chars_multibyte_does_not_panic() {
    // Each char here is a 3-byte UTF-8 sequence; naive byte slicing would panic.
    let s = "こんにちは世界これはテスト"; // 13 Japanese chars
    let result = truncate_chars(s, 5);
    assert_eq!(result, "こんにちは…");
    assert_eq!(result.chars().count(), 6); // 5 chars + ellipsis
}

#[test]
fn truncate_chars_exactly_at_limit() {
    assert_eq!(truncate_chars("hello", 5), "hello");
}

#[test]
fn message_rows_basic_fields() {
    let msgs = vec![test_message("alice", "Hello", "Hi there Bob!", "inbox urgent")];
    let rows = message_rows(&msgs);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].sender, "alice");
    assert_eq!(rows[0].subject, "Hello");
    assert_eq!(rows[0].tags, "inbox, urgent");
    assert_eq!(rows[0].preview, "Hi there Bob!");
}

#[test]
fn message_rows_truncates_long_sender() {
    let long_sender = "a]very_long_sender_name_that_exceeds_twenty_chars";
    let msgs = vec![test_message(long_sender, "Subj", "body", "")];
    let rows = message_rows(&msgs);
    assert!(rows[0].sender.chars().count() <= 20); // 19 chars + "…"
    assert!(rows[0].sender.ends_with('…'));
}

#[test]
fn message_rows_truncates_long_subject() {
    let long_subj = "This is a really long subject line that should be truncated";
    let msgs = vec![test_message("alice", long_subj, "body", "")];
    let rows = message_rows(&msgs);
    assert!(rows[0].subject.chars().count() <= 30); // 29 chars + "…"
    assert!(rows[0].subject.ends_with('…'));
}

#[test]
fn message_rows_truncates_long_preview() {
    let long_body = "This is a very long email body that should definitely be truncated in the preview column";
    let msgs = vec![test_message("alice", "Hi", long_body, "")];
    let rows = message_rows(&msgs);
    assert!(rows[0].preview.chars().count() <= 40); // 39 chars + "…"
    assert!(rows[0].preview.ends_with('…'));
}

#[test]
fn message_rows_empty_tags_show_dash() {
    let msgs = vec![test_message("alice", "Hi", "body", "")];
    let rows = message_rows(&msgs);
    assert_eq!(rows[0].tags, "-");
}

#[test]
fn message_rows_empty_body_shows_dash() {
    let msgs = vec![test_message("alice", "Hi", "", "inbox")];
    let rows = message_rows(&msgs);
    assert_eq!(rows[0].preview, "-");
}

#[test]
fn message_rows_formats_timestamp() {
    let msgs = vec![test_message("alice", "Hi", "body", "")];
    let rows = message_rows(&msgs);
    // Should be in YYYY-MM-DD HH:MM format
    assert!(rows[0].timestamp.len() == 16, "timestamp should be 16 chars: {}", rows[0].timestamp);
}

#[test]
fn message_rows_multiple_messages() {
    let msgs = vec![
        test_message("alice", "First", "body1", "inbox"),
        test_message("bob", "Second", "body2", "sent"),
        test_message("charlie", "Third", "body3", "draft archive"),
    ];
    let rows = message_rows(&msgs);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].sender, "alice");
    assert_eq!(rows[1].sender, "bob");
    assert_eq!(rows[2].tags, "draft, archive");
}

#[test]
fn message_rows_table_renders_without_panic() {
    use tabled::Table;
    let msgs = vec![
        test_message("alice", "Hello", "Preview text here", "inbox urgent"),
    ];
    let rows = message_rows(&msgs);
    let table = Table::new(rows).to_string();
    assert!(table.contains("From"));
    assert!(table.contains("Subject"));
    assert!(table.contains("Tags"));
    assert!(table.contains("Date"));
    assert!(table.contains("Preview"));
    assert!(table.contains("alice"));
    assert!(table.contains("Hello"));
    assert!(table.contains("inbox, urgent"));
}
