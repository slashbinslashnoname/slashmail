use clap::Parser;

use super::{Args, Command};

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
