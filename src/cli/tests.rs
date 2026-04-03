use clap::Parser;

use super::{command_catalogue, message_rows, truncate_chars, Args, Command, DaemonCommand, HelpResult, MessageJson, MessagesResult, SendResult};
use crate::cli::output::{JsonError, JsonSuccess, OutputContext};
use crate::ctl::{CtlRequest, CtlResponse};
use crate::error::AppError;
use crate::storage::db::Message;
use chrono::Utc;
use uuid::Uuid;

/// Helper to parse CLI args from a slice of strings.
fn parse(args: &[&str]) -> Args {
    Args::try_parse_from(args).expect("failed to parse args")
}

/// Unwrap the command from parsed args (panics if None).
fn cmd(args: &Args) -> &Command {
    args.command.as_ref().expect("expected a command")
}

#[test]
fn parse_init() {
    let args = parse(&["slashmail", "init"]);
    assert!(matches!(cmd(&args), Command::Init));
    assert!(!args.json);
}

#[test]
fn parse_status() {
    let args = parse(&["slashmail", "status"]);
    assert!(matches!(cmd(&args), Command::Status));
}

#[test]
fn parse_send_with_to_and_tags() {
    let args = parse(&["slashmail", "send", "--to", "AAAA", "--body", "hello", "--tags", "inbox,urgent"]);
    match cmd(&args) {
        Command::Send { to, body, tags } => {
            assert_eq!(to, "AAAA");
            assert_eq!(body, "hello");
            assert_eq!(tags, &vec!["inbox", "urgent"]);
        }
        _ => panic!("expected Send"),
    }
}

#[test]
fn parse_send_no_tags() {
    let args = parse(&["slashmail", "send", "--to", "BBBB", "--body", "hi"]);
    match cmd(&args) {
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
    match cmd(&args) {
        Command::List { tag } => assert!(tag.is_none()),
        _ => panic!("expected List"),
    }
}

#[test]
fn parse_list_with_tag() {
    let args = parse(&["slashmail", "list", "--tag", "inbox"]);
    match cmd(&args) {
        Command::List { tag } => assert_eq!(tag.as_deref(), Some("inbox")),
        _ => panic!("expected List"),
    }
}

#[test]
fn parse_search() {
    let args = parse(&["slashmail", "search", "hello world"]);
    match cmd(&args) {
        Command::Search { query } => assert_eq!(query, "hello world"),
        _ => panic!("expected Search"),
    }
}

#[test]
fn parse_add_peer() {
    let args = parse(&["slashmail", "add-peer", "/ip4/1.2.3.4/tcp/4001"]);
    match cmd(&args) {
        Command::AddPeer { addr } => assert_eq!(addr, "/ip4/1.2.3.4/tcp/4001"),
        _ => panic!("expected AddPeer"),
    }
}

#[test]
fn parse_peers() {
    let args = parse(&["slashmail", "peers"]);
    assert!(matches!(cmd(&args), Command::Peers));
}

#[test]
fn parse_daemon_start_default_listen() {
    let args = parse(&["slashmail", "daemon", "start"]);
    match cmd(&args) {
        Command::Daemon { action: DaemonCommand::Start { listen } } => {
            assert_eq!(listen, "/ip4/0.0.0.0/tcp/0");
        }
        _ => panic!("expected Daemon Start"),
    }
}

#[test]
fn parse_daemon_start_custom_listen() {
    let args = parse(&["slashmail", "daemon", "start", "--listen", "/ip4/127.0.0.1/tcp/9000"]);
    match cmd(&args) {
        Command::Daemon { action: DaemonCommand::Start { listen } } => {
            assert_eq!(listen, "/ip4/127.0.0.1/tcp/9000");
        }
        _ => panic!("expected Daemon Start"),
    }
}

#[test]
fn parse_daemon_start_short_listen_flag() {
    let args = parse(&["slashmail", "daemon", "start", "-l", "/ip4/0.0.0.0/tcp/5555"]);
    match cmd(&args) {
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
    match cmd(&args) {
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
        cmd(&args),
        Command::Daemon { action: DaemonCommand::Stop }
    ));
}

#[test]
fn parse_daemon_restart_default_listen() {
    let args = parse(&["slashmail", "daemon", "restart"]);
    match cmd(&args) {
        Command::Daemon { action: DaemonCommand::Restart { listen } } => {
            assert_eq!(listen, "/ip4/0.0.0.0/tcp/0");
        }
        _ => panic!("expected Daemon Restart"),
    }
}

#[test]
fn parse_daemon_restart_custom_listen() {
    let args = parse(&["slashmail", "daemon", "restart", "--listen", "/ip4/127.0.0.1/tcp/8000"]);
    match cmd(&args) {
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
    match cmd(&args) {
        Command::Inbox { tag } => assert!(tag.is_none()),
        _ => panic!("expected Inbox"),
    }
}

#[test]
fn parse_inbox_with_tag() {
    let args = parse(&["slashmail", "inbox", "--tag", "urgent"]);
    match cmd(&args) {
        Command::Inbox { tag } => assert_eq!(tag.as_deref(), Some("urgent")),
        _ => panic!("expected Inbox"),
    }
}

#[test]
fn parse_inbox_with_json_flag() {
    let args = parse(&["slashmail", "--json", "inbox"]);
    assert!(args.json);
    assert!(matches!(cmd(&args), Command::Inbox { .. }));
}

#[test]
fn parse_inbox_with_short_tag() {
    let args = parse(&["slashmail", "inbox", "-t", "important"]);
    match cmd(&args) {
        Command::Inbox { tag } => assert_eq!(tag.as_deref(), Some("important")),
        _ => panic!("expected Inbox"),
    }
}

// -- --json flag parsing ---------------------------------------------------

#[test]
fn parse_json_flag_before_subcommand() {
    let args = parse(&["slashmail", "--json", "status"]);
    assert!(args.json);
    assert!(matches!(cmd(&args), Command::Status));
}

#[test]
fn parse_json_flag_after_subcommand() {
    let args = parse(&["slashmail", "list", "--json"]);
    assert!(args.json);
    assert!(matches!(cmd(&args), Command::List { .. }));
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
    match cmd(&args) {
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

// -- Advisory lock file -------------------------------------------------------

#[cfg(unix)]
mod lock_tests {
    use std::os::unix::io::AsRawFd;
    use nix::fcntl::{flock, FlockArg};
    use tempfile::TempDir;

    /// Acquiring a lock on a fresh file succeeds.
    #[test]
    fn acquire_lock_succeeds() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("daemon.lock");

        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
            .unwrap();

        let result = flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock);
        assert!(result.is_ok(), "should acquire lock on fresh file");
    }

    /// A second attempt to lock the same file fails with EWOULDBLOCK.
    #[test]
    fn second_lock_fails() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("daemon.lock");

        let file1 = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        flock(file1.as_raw_fd(), FlockArg::LockExclusiveNonblock).unwrap();

        // Open a second fd and try to lock.
        let file2 = std::fs::OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .unwrap();
        let result = flock(file2.as_raw_fd(), FlockArg::LockExclusiveNonblock);
        assert!(result.is_err(), "second lock should fail");
        assert_eq!(
            result.unwrap_err(),
            nix::errno::Errno::EWOULDBLOCK,
            "error should be EWOULDBLOCK"
        );
    }

    /// Dropping the file releases the lock, allowing re-acquisition.
    #[test]
    fn lock_released_on_drop() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("daemon.lock");

        {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(&lock_path)
                .unwrap();
            flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock).unwrap();
            // file dropped here
        }

        // Should succeed now that the first fd is closed.
        let file2 = std::fs::OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .unwrap();
        let result = flock(file2.as_raw_fd(), FlockArg::LockExclusiveNonblock);
        assert!(result.is_ok(), "lock should be available after drop");
    }
}

// -- No-args handler / help output -------------------------------------------

#[test]
fn parse_no_args_gives_none_command() {
    let args = parse(&["slashmail"]);
    assert!(args.command.is_none());
}

#[test]
fn parse_no_args_with_json_flag() {
    let args = parse(&["slashmail", "--json"]);
    assert!(args.json);
    assert!(args.command.is_none());
}

#[test]
fn command_catalogue_has_all_commands() {
    let cat = command_catalogue();
    let names: Vec<&str> = cat.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"init"));
    assert!(names.contains(&"status"));
    assert!(names.contains(&"send"));
    assert!(names.contains(&"list"));
    assert!(names.contains(&"search"));
    assert!(names.contains(&"add-peer"));
    assert!(names.contains(&"inbox"));
    assert!(names.contains(&"peers"));
    assert!(names.contains(&"daemon start"));
    assert!(names.contains(&"daemon stop"));
    assert!(names.contains(&"daemon restart"));
}

#[test]
fn command_catalogue_descriptions_non_empty() {
    for cmd in command_catalogue() {
        assert!(!cmd.description.is_empty(), "command {} has empty description", cmd.name);
    }
}

#[test]
fn help_result_json_serializes() {
    let result = HelpResult { commands: command_catalogue() };
    let value: serde_json::Value = serde_json::to_value(&result).unwrap();
    assert!(value["commands"].is_array());
    let commands = value["commands"].as_array().unwrap();
    assert!(commands.len() >= 9);
    // Each entry has name, args, description
    for entry in commands {
        assert!(entry["name"].is_string());
        assert!(entry["args"].is_string());
        assert!(entry["description"].is_string());
    }
}

#[test]
fn help_result_json_envelope() {
    // Verify the full JSON envelope via OutputContext
    let ctx = OutputContext::forced(true);
    let result = HelpResult { commands: command_catalogue() };
    // print_success writes to stdout; just verify it doesn't panic
    ctx.print_success(&result, || {
        panic!("human closure should not be called in JSON mode");
    });
}

// -- JSON envelope shape verification ----------------------------------------

#[test]
fn json_success_envelope_has_ok_true_and_data() {
    let data = SendResult {
        message_id: "abc-123".into(),
        recipient: "bob-key".into(),
    };
    let envelope = JsonSuccess::new(&data);
    let json: serde_json::Value = serde_json::to_value(&envelope).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["data"]["message_id"], "abc-123");
    assert_eq!(json["data"]["recipient"], "bob-key");
    // Ensure no extra top-level keys beyond ok and data
    let obj = json.as_object().unwrap();
    assert_eq!(obj.len(), 2);
}

#[test]
fn json_error_envelope_has_ok_false_and_error_fields() {
    let err = AppError::Network("connection refused".into());
    let envelope = JsonError::from_app_error(&err);
    let json: serde_json::Value = serde_json::to_value(&envelope).unwrap();
    assert_eq!(json["ok"], false);
    let error = &json["error"];
    assert!(error["code"].is_string());
    assert!(error["message"].is_string());
    assert!(error["exit_code"].is_number());
    // Top-level has exactly {ok, error}
    assert_eq!(json.as_object().unwrap().len(), 2);
}

#[test]
fn send_result_serializes_all_fields() {
    let result = SendResult {
        message_id: "msg-001".into(),
        recipient: "AAAA".into(),
    };
    let json: serde_json::Value = serde_json::to_value(&result).unwrap();
    assert_eq!(json["message_id"], "msg-001");
    assert_eq!(json["recipient"], "AAAA");
}

#[test]
fn messages_result_empty_list() {
    let result = MessagesResult {
        messages: vec![],
        count: 0,
    };
    let json: serde_json::Value = serde_json::to_value(&result).unwrap();
    assert_eq!(json["count"], 0);
    assert_eq!(json["messages"].as_array().unwrap().len(), 0);
}

#[test]
fn messages_result_with_inbox_messages() {
    let mut m1 = test_message("alice", "Hello", "hi", "urgent");
    m1.folder_path = "INBOX".into();
    let mut m2 = test_message("bob", "Reply", "re: hi", "");
    m2.folder_path = "INBOX".into();

    let json_msgs: Vec<MessageJson> = vec![MessageJson::from(&m1), MessageJson::from(&m2)];
    let result = MessagesResult {
        count: json_msgs.len(),
        messages: json_msgs,
    };
    let json: serde_json::Value = serde_json::to_value(&result).unwrap();
    assert_eq!(json["count"], 2);
    assert_eq!(json["messages"][0]["sender"], "alice");
    assert_eq!(json["messages"][1]["sender"], "bob");
}

// -- CtlRequest/CtlResponse serialization (send command) ---------------------

#[test]
fn ctl_request_send_serializes_with_cmd_tag() {
    let req = CtlRequest::Send {
        to: "recipient-key".into(),
        body: "Hello world".into(),
        tags: vec!["inbox".into(), "important".into()],
    };
    let json: serde_json::Value = serde_json::to_value(&req).unwrap();
    assert_eq!(json["cmd"], "send");
    assert_eq!(json["to"], "recipient-key");
    assert_eq!(json["body"], "Hello world");
    assert_eq!(json["tags"], serde_json::json!(["inbox", "important"]));
}

#[test]
fn ctl_request_send_empty_tags() {
    let req = CtlRequest::Send {
        to: "key".into(),
        body: "msg".into(),
        tags: vec![],
    };
    let json: serde_json::Value = serde_json::to_value(&req).unwrap();
    assert_eq!(json["tags"].as_array().unwrap().len(), 0);
}

#[test]
fn ctl_response_send_ok_deserializes() {
    let json_str = r#"{"type":"send","ok":true,"message_id":"abc-123","error":null}"#;
    let resp: CtlResponse = serde_json::from_str(json_str).unwrap();
    match resp {
        CtlResponse::Send { ok, message_id, error, .. } => {
            assert!(ok);
            assert_eq!(message_id.as_deref(), Some("abc-123"));
            assert!(error.is_none());
        }
        _ => panic!("expected Send response"),
    }
}

#[test]
fn ctl_response_send_error_deserializes() {
    let json_str = r#"{"type":"send","ok":false,"message_id":null,"error":"peer not found"}"#;
    let resp: CtlResponse = serde_json::from_str(json_str).unwrap();
    match resp {
        CtlResponse::Send { ok, error, .. } => {
            assert!(!ok);
            assert_eq!(error.as_deref(), Some("peer not found"));
        }
        _ => panic!("expected Send response"),
    }
}

#[test]
fn ctl_response_send_with_warning() {
    let json_str = r#"{"type":"send","ok":true,"message_id":"x","error":null,"warning":"peer offline, queued"}"#;
    let resp: CtlResponse = serde_json::from_str(json_str).unwrap();
    match resp {
        CtlResponse::Send { ok, warning, .. } => {
            assert!(ok);
            assert_eq!(warning.as_deref(), Some("peer offline, queued"));
        }
        _ => panic!("expected Send response"),
    }
}

#[test]
fn ctl_request_send_roundtrip() {
    let req = CtlRequest::Send {
        to: "pk-base64".into(),
        body: "test body".into(),
        tags: vec!["tag1".into()],
    };
    let serialized = serde_json::to_string(&req).unwrap();
    let deserialized: CtlRequest = serde_json::from_str(&serialized).unwrap();
    match deserialized {
        CtlRequest::Send { to, body, tags } => {
            assert_eq!(to, "pk-base64");
            assert_eq!(body, "test body");
            assert_eq!(tags, vec!["tag1"]);
        }
        _ => panic!("expected Send"),
    }
}

#[test]
fn ctl_response_error_deserializes() {
    let json_str = r#"{"type":"error","message":"daemon busy"}"#;
    let resp: CtlResponse = serde_json::from_str(json_str).unwrap();
    match resp {
        CtlResponse::Error { message } => assert_eq!(message, "daemon busy"),
        _ => panic!("expected Error response"),
    }
}

// -- Inbox data-layer filtering via MessageStore ------------------------------

mod inbox_store_tests {
    use crate::storage::db::{MessageStore, ReadOnlyMessageStore, Message};
    use chrono::Utc;
    use uuid::Uuid;

    fn make_msg(sender: &str, subject: &str, folder: &str) -> Message {
        Message {
            id: Uuid::new_v4(),
            swarm_id: "test-swarm".into(),
            folder_path: folder.into(),
            sender_pubkey: [0u8; 32],
            sender: sender.into(),
            recipient: "me".into(),
            subject: subject.into(),
            body: "body".into(),
            tags: String::new(),
            created_at: Utc::now(),
            read: false,
        }
    }

    #[test]
    fn inbox_messages_filters_by_inbox_folder() {
        let store = MessageStore::open_memory().unwrap();
        store.insert_message(&make_msg("alice", "Hi", "INBOX")).unwrap();
        store.insert_message(&make_msg("bob", "Re", "SENT")).unwrap();
        store.insert_message(&make_msg("carol", "Hey", "INBOX")).unwrap();

        // Can't open ReadOnlyMessageStore from memory DB, so query directly
        let conn = store.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id FROM messages WHERE folder_path = 'INBOX' ORDER BY created_at DESC",
            )
            .unwrap();
        let ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn inbox_messages_by_tag_filters_correctly() {
        let store = MessageStore::open_memory().unwrap();
        let m1 = make_msg("alice", "Urgent", "INBOX");
        let m2 = make_msg("bob", "Normal", "INBOX");
        let m3 = make_msg("carol", "Sent", "SENT");

        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();
        store.insert_message(&m3).unwrap();

        store.tag_message(&m1.id, "urgent").unwrap();
        store.tag_message(&m2.id, "normal").unwrap();
        store.tag_message(&m3.id, "urgent").unwrap();

        // Query: INBOX messages with tag "urgent" → only m1
        let conn = store.conn();
        let mut stmt = conn
            .prepare(
                "SELECT m.id FROM messages m
                 JOIN message_tags mt ON m.id = mt.envelope_id
                 WHERE m.folder_path = 'INBOX' AND mt.tag = 'urgent'
                 ORDER BY m.created_at DESC",
            )
            .unwrap();
        let ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], m1.id.to_string());
    }

    #[test]
    fn inbox_messages_respects_limit() {
        let store = MessageStore::open_memory().unwrap();
        for i in 0..10 {
            store
                .insert_message(&make_msg("alice", &format!("Msg {i}"), "INBOX"))
                .unwrap();
        }

        let conn = store.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id FROM messages WHERE folder_path = 'INBOX' ORDER BY created_at DESC LIMIT 3",
            )
            .unwrap();
        let ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn search_passthrough_finds_matching_messages() {
        let store = MessageStore::open_memory().unwrap();
        let m1 = make_msg("alice", "Meeting notes", "INBOX");
        let m2 = make_msg("bob", "Lunch plans", "INBOX");

        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();

        let results = store.search_messages("meeting").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subject, "Meeting notes");
    }

    #[test]
    fn search_passthrough_returns_empty_for_no_match() {
        let store = MessageStore::open_memory().unwrap();
        store
            .insert_message(&make_msg("alice", "Hello", "INBOX"))
            .unwrap();

        let results = store.search_messages("nonexistent").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn inbox_empty_returns_empty_vec() {
        let store = MessageStore::open_memory().unwrap();
        // Insert only SENT messages
        store
            .insert_message(&make_msg("alice", "Sent item", "SENT"))
            .unwrap();

        let conn = store.conn();
        let mut stmt = conn
            .prepare("SELECT id FROM messages WHERE folder_path = 'INBOX'")
            .unwrap();
        let ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(ids.is_empty());
    }
}

// -- Daemon PID stale detection -----------------------------------------------

#[cfg(unix)]
mod daemon_pid_tests {
    /// is_pid_alive correctly identifies current process as alive.
    #[test]
    fn current_process_is_alive() {
        assert!(super::super::is_pid_alive(std::process::id()));
    }

    /// A very high PID that doesn't exist should be reported as not alive.
    #[test]
    fn nonexistent_pid_is_not_alive() {
        assert!(!super::super::is_pid_alive(4_000_000));
    }

    /// PID 0 is special (kernel) — is_pid_alive should handle it without panic.
    #[test]
    fn pid_zero_does_not_panic() {
        // Result varies by platform, but should not panic.
        let _ = super::super::is_pid_alive(0);
    }

    /// Verify PID file write and read produce consistent data.
    #[test]
    fn pid_file_write_read_remove_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let pid_path = dir.path().join("daemon.pid");
        let pid = std::process::id();

        // Write
        std::fs::write(&pid_path, pid.to_string()).unwrap();

        // Read
        let contents = std::fs::read_to_string(&pid_path).unwrap();
        let read_pid: u32 = contents.trim().parse().unwrap();
        assert_eq!(read_pid, pid);

        // Remove
        std::fs::remove_file(&pid_path).unwrap();
        assert!(!pid_path.exists());
    }

    /// Stale PID file with dead process should be detectable.
    #[test]
    fn stale_pid_detection() {
        let dir = tempfile::TempDir::new().unwrap();
        let pid_path = dir.path().join("daemon.pid");

        // Write a PID that doesn't exist
        std::fs::write(&pid_path, "4000000").unwrap();

        // Read it back
        let contents = std::fs::read_to_string(&pid_path).unwrap();
        let pid: u32 = contents.trim().parse().unwrap();

        // Detect it's stale
        assert!(!super::super::is_pid_alive(pid));

        // Cleanup (simulating what run_daemon_stop does with stale PIDs)
        std::fs::remove_file(&pid_path).unwrap();
        assert!(!pid_path.exists());
    }

    /// PID file with trailing newline/whitespace parses correctly.
    #[test]
    fn pid_file_with_newline() {
        let dir = tempfile::TempDir::new().unwrap();
        let pid_path = dir.path().join("daemon.pid");
        std::fs::write(&pid_path, "12345\n").unwrap();

        let contents = std::fs::read_to_string(&pid_path).unwrap();
        let pid: u32 = contents.trim().parse().unwrap();
        assert_eq!(pid, 12345);
    }

    /// Empty PID file fails to parse (simulating corruption).
    #[test]
    fn empty_pid_file_fails_parse() {
        let dir = tempfile::TempDir::new().unwrap();
        let pid_path = dir.path().join("daemon.pid");
        std::fs::write(&pid_path, "").unwrap();

        let contents = std::fs::read_to_string(&pid_path).unwrap();
        assert!(contents.trim().parse::<u32>().is_err());
    }
}

// -- OutputContext: print_error returns correct codes for all error types ------

#[test]
fn print_error_json_mode_network() {
    let ctx = OutputContext::forced(true);
    let err = AppError::Network("timeout".into());
    let code = ctx.print_error(&err);
    assert_eq!(code, crate::cli::output::ExitCode::NetworkError);
}

#[test]
fn print_error_json_mode_crypto() {
    let ctx = OutputContext::forced(true);
    let err = AppError::Crypto("bad key".into());
    let code = ctx.print_error(&err);
    assert_eq!(code, crate::cli::output::ExitCode::CryptoError);
}

#[test]
fn print_error_human_mode_returns_code_without_panic() {
    let ctx = OutputContext::forced(false);
    let err = AppError::InvalidInput("bad".into());
    let code = ctx.print_error(&err);
    assert_eq!(code, crate::cli::output::ExitCode::InvalidInput);
}
