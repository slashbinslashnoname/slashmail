//! End-to-end integration tests for slashmail.
//!
//! Three areas are covered:
//!   1. Send-to-inbox roundtrip: envelope → encode → decode → store → query → verify fields.
//!   2. Daemon gossipsub loop: two in-process swarms, connect, publish on one, assert decode
//!      on the other.
//!   3. Structured output: run the binary with `--json`, assert the JSON envelope schema.

use std::process::Command;
use std::time::Duration;

use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::Signature;
use futures::StreamExt as _;
use libp2p::gossipsub;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use tokio::sync::mpsc;
use uuid::Uuid;

use slashmail::crypto::signing::{self, generate_keypair};
use slashmail::engine::{EngineCommand, ShutdownReason};
use slashmail::identity::Identity;
use slashmail::message::codec;
use slashmail::net;
use slashmail::storage::db::{Message, MessageStore};
use slashmail::types::Envelope;

// ───────────────────────────────────────────────────────────────────────────
// 1. Send-to-inbox roundtrip
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn send_to_inbox_roundtrip_public_message() {
    let kp = generate_keypair();
    let pubkey = kp.verifying_key().to_bytes();
    let body_text = "Hello from the integration test!";

    // Build and encode an envelope.
    let mut envelope = Envelope::new(pubkey, "pub_general".into(), body_text.as_bytes().to_vec());
    envelope.tags = vec!["important".into(), "test".into()];
    let original_id = envelope.id;
    let original_ts = envelope.timestamp;

    let encoded = codec::encode(&envelope, &kp).expect("encode should succeed");

    // Decode and verify signature.
    let decoded = codec::decode(&encoded).expect("decode should succeed");
    assert_eq!(decoded.id, original_id);
    assert_eq!(decoded.sender_pubkey, pubkey);
    assert_eq!(decoded.swarm_id, "pub_general");
    assert_eq!(decoded.payload, body_text.as_bytes());
    assert_eq!(decoded.tags, vec!["important", "test"]);
    assert_eq!(decoded.timestamp, original_ts);

    let sig = Signature::from_slice(&decoded.signature).expect("valid signature bytes");
    signing::verify(&kp.verifying_key(), &decoded.payload, &sig)
        .expect("signature should verify");

    // Store the decoded envelope as a Message in the database.
    let b64 = base64::engine::general_purpose::STANDARD;
    let store = MessageStore::open_memory().expect("in-memory store");
    let msg = Message {
        id: decoded.id,
        swarm_id: decoded.swarm_id.clone(),
        folder_path: "INBOX".into(),
        sender_pubkey: decoded.sender_pubkey,
        sender: b64.encode(decoded.sender_pubkey),
        recipient: String::new(),
        subject: String::new(),
        body: String::from_utf8(decoded.payload.clone()).unwrap(),
        tags: decoded.tags.join(" "),
        created_at: decoded.timestamp,
        read: false,
    };
    store.insert_message(&msg).expect("insert should succeed");

    // Query back and verify all fields.
    let messages = store.list_messages(0).expect("list should succeed");
    assert_eq!(messages.len(), 1);
    let stored = &messages[0];
    assert_eq!(stored.id, original_id);
    assert_eq!(stored.swarm_id, "pub_general");
    assert_eq!(stored.folder_path, "INBOX");
    assert_eq!(stored.sender_pubkey, pubkey);
    assert_eq!(stored.sender, b64.encode(pubkey));
    assert_eq!(stored.body, body_text);
    assert_eq!(stored.tags, "important test");
    assert!(!stored.read);
}

#[test]
fn send_to_inbox_roundtrip_with_tags_and_search() {
    let kp = generate_keypair();
    let pubkey = kp.verifying_key().to_bytes();
    let b64 = base64::engine::general_purpose::STANDARD;
    let store = MessageStore::open_memory().expect("in-memory store");

    // Insert two messages with different tags.
    for (i, (body, tags)) in [
        ("First message", vec!["alpha", "beta"]),
        ("Second message", vec!["gamma"]),
    ]
    .iter()
    .enumerate()
    {
        let envelope = Envelope::new(pubkey, "pub_test".into(), body.as_bytes().to_vec());
        let encoded = codec::encode(&envelope, &kp).unwrap();
        let decoded = codec::decode(&encoded).unwrap();

        let msg = Message {
            id: decoded.id,
            swarm_id: decoded.swarm_id.clone(),
            folder_path: "INBOX".into(),
            sender_pubkey: pubkey,
            sender: b64.encode(pubkey),
            recipient: String::new(),
            subject: format!("Subject #{}", i + 1),
            body: body.to_string(),
            tags: tags.join(" "),
            created_at: decoded.timestamp,
            read: false,
        };
        store.insert_message(&msg).unwrap();

        // Also insert into the normalised tag table.
        let tag_refs: Vec<&str> = tags.iter().copied().collect();
        store.upsert_tags(&msg.id, &tag_refs).unwrap();
    }

    // list_messages returns both, newest first.
    let all = store.list_messages(0).unwrap();
    assert_eq!(all.len(), 2);

    // FTS search for "Second" should find only the second message.
    let results = store.search_messages("Second").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].body, "Second message");

    // Tag query: "alpha" should match first message only.
    let by_tag = store.messages_by_tag("alpha").unwrap();
    assert_eq!(by_tag.len(), 1);
    assert_eq!(by_tag[0].body, "First message");
}

#[test]
fn send_to_inbox_multiple_messages_ordered_by_time() {
    let kp = generate_keypair();
    let pubkey = kp.verifying_key().to_bytes();
    let b64 = base64::engine::general_purpose::STANDARD;
    let store = MessageStore::open_memory().expect("in-memory store");

    // Insert messages with explicitly ordered timestamps.
    let base_time = Utc::now();
    for i in 0..5 {
        let ts = base_time + chrono::Duration::seconds(i as i64);
        let msg = Message {
            id: Uuid::new_v4(),
            swarm_id: "pub_test".into(),
            folder_path: "INBOX".into(),
            sender_pubkey: pubkey,
            sender: b64.encode(pubkey),
            recipient: String::new(),
            subject: String::new(),
            body: format!("message_{i}"),
            tags: String::new(),
            created_at: ts,
            read: false,
        };
        store.insert_message(&msg).unwrap();
    }

    let all = store.list_messages(0).unwrap();
    assert_eq!(all.len(), 5);
    // Newest first (DESC order).
    assert_eq!(all[0].body, "message_4");
    assert_eq!(all[4].body, "message_0");

    // Limit should work.
    let limited = store.list_messages(2).unwrap();
    assert_eq!(limited.len(), 2);
    assert_eq!(limited[0].body, "message_4");
}

// ───────────────────────────────────────────────────────────────────────────
// 2. Daemon gossipsub loop: two in-process swarms
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn two_swarm_gossipsub_publish_and_receive() {
    // Create two identities with their own swarms.
    let id_a = Identity::generate();
    let id_b = Identity::generate();

    let (mut swarm_a, _peer_a) = net::build_swarm(&id_a).await.unwrap();
    let (mut swarm_b, _peer_b) = net::build_swarm(&id_b).await.unwrap();

    // Swarm A listens on a random TCP port.
    swarm_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap())
        .unwrap();

    // Poll swarm A until we get a listen address.
    let listen_addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm_a.select_next_some().await {
            if address.to_string().contains("tcp") {
                break address;
            }
        }
    };

    // Swarm B dials swarm A.
    swarm_b.dial(listen_addr).unwrap();

    // Both subscribe to the same gossipsub topic.
    let topic = gossipsub::Sha256Topic::new("pub_e2e_test");
    swarm_a.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    swarm_b.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

    // Poll both swarms until they are connected and have exchanged gossipsub subscriptions.
    // We need mesh peers before publishing works, so we wait for gossipsub heartbeats.
    let timeout = tokio::time::Instant::now() + Duration::from_secs(15);

    // Wait for connection + mesh formation.
    loop {
        if tokio::time::Instant::now() > timeout {
            panic!("timeout waiting for gossipsub mesh formation");
        }
        tokio::select! {
            _ = swarm_a.select_next_some() => {},
            _ = swarm_b.select_next_some() => {},
            _ = tokio::time::sleep(Duration::from_millis(50)) => {},
        }

        // Check if swarm_a has mesh peers for the topic.
        let mesh_a = swarm_a
            .behaviour()
            .gossipsub
            .mesh_peers(&topic.hash())
            .count();
        let mesh_b = swarm_b
            .behaviour()
            .gossipsub
            .mesh_peers(&topic.hash())
            .count();
        if mesh_a > 0 && mesh_b > 0 {
            break;
        }
    }

    // Encode a message from identity A.
    let kp_a = id_a.keypair().clone();
    let envelope = Envelope::new(
        kp_a.verifying_key().to_bytes(),
        "pub_e2e_test".into(),
        b"gossipsub roundtrip test".to_vec(),
    );
    let encoded = codec::encode(&envelope, &kp_a).unwrap();
    let original_id = envelope.id;

    // Publish on swarm A.
    swarm_a
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), encoded.clone())
        .expect("publish should succeed with mesh peers");

    // Poll both swarms until swarm B receives the gossipsub message.
    // swarm_a must also be polled to keep the connection alive.
    let message = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = swarm_b.select_next_some() => {
                    if let SwarmEvent::Behaviour(slashmail::net::behaviour::SlashmailBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. },
                    )) = event
                    {
                        return message;
                    }
                }
                _ = swarm_a.select_next_some() => {}
            }
        }
    })
    .await
    .expect("timeout waiting for gossipsub message on swarm B");
    let decoded = codec::decode(&message.data).expect("decode received message");
    assert_eq!(decoded.id, original_id);
    assert_eq!(decoded.payload, b"gossipsub roundtrip test");

    // Verify signature.
    let sig = Signature::from_slice(&decoded.signature).unwrap();
    signing::verify(&kp_a.verifying_key(), &decoded.payload, &sig)
        .expect("signature from gossipsub message should verify");
}

#[tokio::test]
async fn engine_run_loop_insert_and_shutdown() {
    // Test that the engine event loop can insert messages and shut down gracefully.
    // Pattern mirrors the engine unit tests: pre-queue commands, then call run_loop directly
    // (MessageStore is not Send so tokio::spawn cannot be used here).
    let identity = Identity::generate();
    let (swarm, _peer_id) = net::build_swarm(&identity).await.unwrap();
    let store = MessageStore::open_memory().unwrap();

    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let kp = identity.keypair().clone();

    // Build the message using the keypair before sending it to the engine.
    let b64 = base64::engine::general_purpose::STANDARD;
    let msg = Message {
        id: Uuid::new_v4(),
        swarm_id: "pub_test".into(),
        folder_path: "INBOX".into(),
        sender_pubkey: kp.verifying_key().to_bytes(),
        sender: b64.encode(kp.verifying_key().to_bytes()),
        recipient: String::new(),
        subject: String::new(),
        body: "engine test message".into(),
        tags: String::new(),
        created_at: Utc::now(),
        read: false,
    };

    // Pre-queue: InsertMessage then Shutdown.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(EngineCommand::InsertMessage {
            msg,
            reply: reply_tx,
        })
        .await
        .unwrap();
    cmd_tx.send(EngineCommand::Shutdown).await.unwrap();

    // Run the loop to completion (not spawned — MessageStore is !Send).
    let reason = slashmail::engine::run_loop(swarm, cmd_rx, Some(store), None, Some(&kp)).await;
    assert_eq!(reason, ShutdownReason::Command);

    // The reply is available after the loop exits.
    reply_rx.await.unwrap().expect("insert should succeed");
}

#[tokio::test]
async fn engine_channel_closed_shutdown() {
    let identity = Identity::generate();
    let (swarm, _) = net::build_swarm(&identity).await.unwrap();

    let (cmd_tx, cmd_rx) = mpsc::channel(16);

    // Drop all senders → engine should detect ChannelClosed.
    drop(cmd_tx);

    let reason = slashmail::engine::run_loop(swarm, cmd_rx, None, None, None).await;
    assert_eq!(reason, ShutdownReason::ChannelClosed);
}

#[tokio::test]
async fn engine_get_status() {
    let identity = Identity::generate();
    let (swarm, _) = net::build_swarm(&identity).await.unwrap();
    let expected_peer_id = swarm.local_peer_id().to_string();

    let (cmd_tx, cmd_rx) = mpsc::channel(16);

    // Pre-queue: GetStatus then Shutdown.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(EngineCommand::GetStatus { reply: reply_tx })
        .await
        .unwrap();
    cmd_tx.send(EngineCommand::Shutdown).await.unwrap();

    // Run to completion.
    slashmail::engine::run_loop(swarm, cmd_rx, None, None, None).await;

    // Replies are available after the loop exits.
    let status = reply_rx.await.unwrap();
    assert_eq!(status.peer_id, expected_peer_id);
    assert_eq!(status.num_peers, 0);
}

// ───────────────────────────────────────────────────────────────────────────
// 3. Structured output: binary JSON schema assertions
// ───────────────────────────────────────────────────────────────────────────

/// Run the slashmail binary with given args and return (stdout, stderr, exit_code).
///
/// `RUST_LOG` is set to `off` so that tracing output does not pollute stdout and
/// interfere with JSON parsing.
fn run_binary(args: &[&str]) -> (String, String, i32) {
    let binary = env!("CARGO_BIN_EXE_slashmail");
    let output = Command::new(binary)
        .args(args)
        .env("HOME", "/tmp/slashmail_e2e_test_nonexistent")
        .env("RUST_LOG", "off")
        .output()
        .expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

#[test]
fn json_output_no_command_returns_help_schema() {
    let (stdout, _stderr, code) = run_binary(&["--json"]);
    assert_eq!(code, 0, "exit code should be 0 for help");

    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\nstdout: {stdout}"));

    // Verify the JSON success envelope structure.
    assert_eq!(parsed["ok"], true);
    assert!(parsed["data"]["commands"].is_array(), "data.commands should be an array");

    let commands = parsed["data"]["commands"].as_array().unwrap();
    assert!(!commands.is_empty(), "command catalogue should not be empty");

    // Each command entry should have name, args, description.
    for cmd in commands {
        assert!(cmd["name"].is_string(), "command.name should be a string");
        assert!(cmd["description"].is_string(), "command.description should be a string");
    }

    // Verify known commands are present.
    let names: Vec<&str> = commands
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"init"), "should contain 'init' command");
    assert!(names.contains(&"status"), "should contain 'status' command");
    assert!(names.contains(&"send"), "should contain 'send' command");
    assert!(names.contains(&"list"), "should contain 'list' command");
    assert!(names.contains(&"inbox"), "should contain 'inbox' command");
}

#[test]
fn json_output_list_empty_db() {
    // Use a temp dir that has no database — should return empty messages.
    let tmp = tempfile::tempdir().unwrap();
    let (stdout, _stderr, code) = {
        let binary = env!("CARGO_BIN_EXE_slashmail");
        let output = Command::new(binary)
            .args(["--json", "list"])
            .env("HOME", tmp.path())
            .env("RUST_LOG", "off")
            .output()
            .expect("failed to execute binary");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        (stdout, stderr, output.status.code().unwrap_or(-1))
    };
    assert_eq!(code, 0, "list with no db should succeed");

    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not valid JSON: {e}\nstdout: {stdout}"));

    assert_eq!(parsed["ok"], true);
    assert!(parsed["data"]["messages"].is_array());
    assert_eq!(parsed["data"]["count"], 0);
    assert_eq!(parsed["data"]["messages"].as_array().unwrap().len(), 0);
}

#[test]
fn json_output_search_empty_db() {
    let tmp = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_slashmail");
    let output = Command::new(binary)
        .args(["--json", "search", "nonexistent"])
        .env("HOME", tmp.path())
        .env("RUST_LOG", "off")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(code, 0);

    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not valid JSON: {e}\nstdout: {stdout}"));
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["data"]["count"], 0);
}

#[test]
fn json_output_inbox_empty_db() {
    let tmp = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_slashmail");
    let output = Command::new(binary)
        .args(["--json", "inbox"])
        .env("HOME", tmp.path())
        .env("RUST_LOG", "off")
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(code, 0);

    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not valid JSON: {e}\nstdout: {stdout}"));
    assert_eq!(parsed["ok"], true);
    assert!(parsed["data"]["messages"].is_array());
    assert_eq!(parsed["data"]["count"], 0);
}

#[test]
fn json_output_envelope_has_ok_field() {
    // All JSON responses must have an "ok" field at the top level.
    let (stdout, _, code) = run_binary(&["--json"]);
    assert_eq!(code, 0);

    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        parsed.get("ok").is_some(),
        "JSON envelope must have 'ok' field"
    );
    assert!(
        parsed["ok"].is_boolean(),
        "'ok' field must be a boolean"
    );
}
