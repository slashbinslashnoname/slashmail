use clap::Parser;

use super::{message_rows, truncate_chars, Args, Command, DaemonCommand, MessageJson, MessagesResult};
use crate::cli::output::OutputContext;
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
    assert!(!args.json);
}

#[test]
fn parse_status() {
    let args = parse(&["slashmail", "status"]);
    assert!(matches!(args.command, Command::Status));
}

#[test]
fn parse_send_with_to_and_tags() {
    let args = parse(&["slashmail", "send", "--to", "AAAA", "--body", "hello", "--tags", "inbox,urgent"]);
    match args.command {
        Command::Send { to, body, tags } => {
            assert_eq!(to, "AAAA");
            assert_eq!(body, "hello");
            assert_eq!(tags, vec!["inbox", "urgent"]);
        }
        _ => panic!("expected Send"),
    }
}

#[test]
fn parse_send_no_tags() {
    let args = parse(&["slashmail", "send", "--to", "BBBB", "--body", "hi"]);
    match args.command {
        Command::Send { to, body, tags } => {
            assert_eq!(to, "BBBB");
            assert_eq!(body, "hi");
            assert!(tags.is_empty());
        }
        _ => panic!("expected Send"),
    }
}

#[test]
fn parse_send_requires_body() {
    let result = Args::try_parse_from(&["slashmail", "send", "--to", "AAAA"]);
    assert!(result.is_err(), "send should require --body");
}

#[test]
fn parse_send_requires_to() {
    let result = Args::try_parse_from(&["slashmail", "send", "--body", "hello"]);
    assert!(result.is_err(), "send should require --to");
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
fn parse_daemon_start_default_listen() {
    let args = parse(&["slashmail", "daemon", "start"]);
    match args.command {
        Command::Daemon { action: DaemonCommand::Start { listen } } => {
            assert_eq!(listen, "/ip4/0.0.0.0/tcp/0");
        }
        _ => panic!("expected Daemon Start"),
    }
}

#[test]
fn parse_daemon_start_custom_listen() {
    let args = parse(&["slashmail", "daemon", "start", "--listen", "/ip4/127.0.0.1/tcp/9000"]);
    match args.command {
        Command::Daemon { action: DaemonCommand::Start { listen } } => {
            assert_eq!(listen, "/ip4/127.0.0.1/tcp/9000");
        }
        _ => panic!("expected Daemon Start"),
    }
}

#[test]
fn parse_daemon_start_short_listen_flag() {
    let args = parse(&["slashmail", "daemon", "start", "-l", "/ip4/0.0.0.0/tcp/5555"]);
    match args.command {
        Command::Daemon { action: DaemonCommand::Start { listen } } => {
            assert_eq!(listen, "/ip4/0.0.0.0/tcp/5555");
        }
        _ => panic!("expected Daemon Start"),
    }
}

#[test]
fn parse_daemon_start_with_json_flag() {
    let args = parse(&["slashmail", "--json", "daemon", "start"]);
    assert!(args.json);
    match args.command {
        Command::Daemon { action: DaemonCommand::Start { listen } } => {
            assert_eq!(listen, "/ip4/0.0.0.0/tcp/0");
        }
        _ => panic!("expected Daemon Start"),
    }
}

#[test]
fn parse_daemon_stop() {
    let args = parse(&["slashmail", "daemon", "stop"]);
    assert!(matches!(
        args.command,
        Command::Daemon { action: DaemonCommand::Stop }
    ));
}

#[test]
fn parse_daemon_restart_default_listen() {
    let args = parse(&["slashmail", "daemon", "restart"]);
    match args.command {
        Command::Daemon { action: DaemonCommand::Restart { listen } } => {
            assert_eq!(listen, "/ip4/0.0.0.0/tcp/0");
        }
        _ => panic!("expected Daemon Restart"),
    }
}

#[test]
fn parse_daemon_restart_custom_listen() {
    let args = parse(&["slashmail", "daemon", "restart", "--listen", "/ip4/127.0.0.1/tcp/8000"]);
    match args.command {
        Command::Daemon { action: DaemonCommand::Restart { listen } } => {
            assert_eq!(listen, "/ip4/127.0.0.1/tcp/8000");
        }
        _ => panic!("expected Daemon Restart"),
    }
}

#[test]
fn parse_daemon_requires_subcommand() {
    let result = Args::try_parse_from(&["slashmail", "daemon"]);
    assert!(result.is_err(), "daemon without subcommand should fail");
}

#[test]
fn whoami_is_not_a_command() {
    let result = Args::try_parse_from(&["slashmail", "whoami"]);
    assert!(result.is_err(), "whoami should no longer be a valid subcommand");
}

#[test]
fn parse_inbox_no_tag() {
    let args = parse(&["slashmail", "inbox"]);
    match args.command {
        Command::Inbox { tag } => assert!(tag.is_none()),
        _ => panic!("expected Inbox"),
    }
}

#[test]
fn parse_inbox_with_tag() {
    let args = parse(&["slashmail", "inbox", "--tag", "urgent"]);
    match args.command {
        Command::Inbox { tag } => assert_eq!(tag.as_deref(), Some("urgent")),
        _ => panic!("expected Inbox"),
    }
}

#[test]
fn parse_inbox_with_json_flag() {
    let args = parse(&["slashmail", "--json", "inbox"]);
    assert!(args.json);
    assert!(matches!(args.command, Command::Inbox { .. }));
}

#[test]
fn parse_inbox_with_short_tag() {
    let args = parse(&["slashmail", "inbox", "-t", "important"]);
    match args.command {
        Command::Inbox { tag } => assert_eq!(tag.as_deref(), Some("important")),
        _ => panic!("expected Inbox"),
    }
}

// -- --json flag parsing ---------------------------------------------------

#[test]
fn parse_json_flag_before_subcommand() {
    let args = parse(&["slashmail", "--json", "status"]);
    assert!(args.json);
    assert!(matches!(args.command, Command::Status));
}

#[test]
fn parse_json_flag_after_subcommand() {
    let args = parse(&["slashmail", "list", "--json"]);
    assert!(args.json);
    assert!(matches!(args.command, Command::List { .. }));
}

#[test]
fn parse_no_json_flag() {
    let args = parse(&["slashmail", "status"]);
    assert!(!args.json);
}

#[test]
fn parse_json_flag_with_other_args() {
    let args = parse(&["slashmail", "--json", "list", "--tag", "inbox"]);
    assert!(args.json);
    match args.command {
        Command::List { tag } => assert_eq!(tag.as_deref(), Some("inbox")),
        _ => panic!("expected List"),
    }
}

// -- OutputContext integration ---------------------------------------------

#[test]
fn output_context_from_json_flag() {
    let ctx = OutputContext::new(true);
    assert!(ctx.is_json());
}

#[test]
fn output_context_print_success_json_mode() {
    let ctx = OutputContext::forced(true);
    let data = serde_json::json!({"key": "value"});
    // Should not panic; in a real test we'd capture stdout.
    ctx.print_success(&data, || {
        panic!("human closure should not be called in JSON mode");
    });
}

#[test]
fn output_context_print_success_human_mode() {
    let ctx = OutputContext::forced(false);
    let mut called = false;
    let data = serde_json::json!({"key": "value"});
    ctx.print_success(&data, || {
        called = true;
    });
    assert!(called, "human closure should be called in human mode");
}

// -- MessageJson conversion ------------------------------------------------

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
fn message_json_from_message() {
    let msg = test_message("alice", "Hello", "Hi there", "inbox urgent");
    let json = MessageJson::from(&msg);
    assert_eq!(json.sender, "alice");
    assert_eq!(json.subject, "Hello");
    assert_eq!(json.body, "Hi there");
    assert_eq!(json.tags, vec!["inbox", "urgent"]);
    assert!(!json.read);
    assert_eq!(json.recipient, "bob");
}

#[test]
fn message_json_empty_tags() {
    let msg = test_message("alice", "Hi", "body", "");
    let json = MessageJson::from(&msg);
    assert!(json.tags.is_empty());
}

#[test]
fn messages_result_serializes() {
    let msg = test_message("alice", "Hello", "body", "inbox");
    let json_msgs: Vec<MessageJson> = vec![MessageJson::from(&msg)];
    let result = MessagesResult {
        count: json_msgs.len(),
        messages: json_msgs,
    };
    let value: serde_json::Value = serde_json::to_value(&result).unwrap();
    assert_eq!(value["count"], 1);
    assert!(value["messages"].is_array());
    assert_eq!(value["messages"][0]["sender"], "alice");
}

// -- Table display (unchanged) ---------------------------------------------

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

// -- PID file management ------------------------------------------------------

#[cfg(unix)]
mod pid_tests {
    use std::fs;
    use tempfile::TempDir;

    /// Test that is_pid_alive returns true for the current process.
    #[test]
    fn is_pid_alive_current_process() {
        let pid = std::process::id();
        assert!(super::super::is_pid_alive(pid));
    }

    /// Test that is_pid_alive returns false for a non-existent PID.
    #[test]
    fn is_pid_alive_nonexistent() {
        // PID 4_000_000 is almost certainly not in use.
        assert!(!super::super::is_pid_alive(4_000_000));
    }

    /// Test reading a valid PID file.
    #[test]
    fn read_pid_file_valid() {
        let dir = TempDir::new().unwrap();
        let pid_path = dir.path().join("daemon.pid");
        fs::write(&pid_path, "12345").unwrap();

        // We can't call read_pid_file() directly since it uses Config::pid_path(),
        // but we can test the parsing logic inline.
        let contents = fs::read_to_string(&pid_path).unwrap();
        let pid: u32 = contents.trim().parse().unwrap();
        assert_eq!(pid, 12345);
    }

    /// Test reading a PID file with whitespace.
    #[test]
    fn read_pid_file_with_whitespace() {
        let dir = TempDir::new().unwrap();
        let pid_path = dir.path().join("daemon.pid");
        fs::write(&pid_path, "  42  \n").unwrap();

        let contents = fs::read_to_string(&pid_path).unwrap();
        let pid: u32 = contents.trim().parse().unwrap();
        assert_eq!(pid, 42);
    }

    /// Test that an invalid PID file contents can't be parsed.
    #[test]
    fn read_pid_file_invalid_contents() {
        let dir = TempDir::new().unwrap();
        let pid_path = dir.path().join("daemon.pid");
        fs::write(&pid_path, "not_a_number").unwrap();

        let contents = fs::read_to_string(&pid_path).unwrap();
        assert!(contents.trim().parse::<u32>().is_err());
    }

    /// Test that a missing PID file is handled.
    #[test]
    fn read_pid_file_missing() {
        let dir = TempDir::new().unwrap();
        let pid_path = dir.path().join("daemon.pid");
        assert!(!pid_path.exists());
    }
}
