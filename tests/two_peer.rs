//! Two-peer integration tests.
//!
//! Three scenarios are covered:
//!   1. Private message send/receive with encrypted tags via request-response.
//!   2. FTS5 full-text search by body and tag on received messages.
//!   3. Delta-sync of 3 messages to a late-joining peer via Merkle protocol.

use std::time::Duration;

use base64::Engine as _;
use futures::StreamExt as _;
use libp2p::request_response::{Event as RrEvent, Message as RrMessage};
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use uuid::Uuid;

use slashmail::crypto::ecdh;
use slashmail::crypto::encryption;
use slashmail::crypto::signing::generate_keypair;
use slashmail::engine::merkle::MerkleTree;
use slashmail::identity::Identity;
use slashmail::message::codec;
use slashmail::net;
use slashmail::net::behaviour::SlashmailBehaviourEvent;
use slashmail::net::rr::{MailRequest, MailResponse};
use slashmail::net::sync_rr::{SyncRequest, SyncResponse};
use slashmail::storage::db::{Message, MessageStore};
use slashmail::types::Envelope;

/// Build two swarms, connect them over TCP on ephemeral ports, and wait until
/// both report the connection as established.
async fn connect_two_swarms() -> (
    libp2p::Swarm<slashmail::net::behaviour::SlashmailBehaviour>,
    libp2p::Swarm<slashmail::net::behaviour::SlashmailBehaviour>,
    Identity,
    Identity,
) {
    let id_a = Identity::generate();
    let id_b = Identity::generate();

    let (mut swarm_a, _) = net::build_swarm(&id_a).await.unwrap();
    let (mut swarm_b, _) = net::build_swarm(&id_b).await.unwrap();

    // Swarm A listens on an ephemeral TCP port.
    swarm_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap())
        .unwrap();

    // Poll until we get a TCP listen address.
    let listen_addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm_a.select_next_some().await {
            if address.to_string().contains("tcp") {
                break address;
            }
        }
    };

    // Swarm B dials Swarm A.
    swarm_b.dial(listen_addr).unwrap();

    // Wait for both to report ConnectionEstablished.
    let timeout = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut a_connected = false;
    let mut b_connected = false;

    while !a_connected || !b_connected {
        if tokio::time::Instant::now() > timeout {
            panic!("timeout waiting for peer connection");
        }
        tokio::select! {
            event = swarm_a.select_next_some() => {
                if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                    a_connected = true;
                }
            }
            event = swarm_b.select_next_some() => {
                if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                    b_connected = true;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    (swarm_a, swarm_b, id_a, id_b)
}

/// Derive PeerId from an Ed25519 public key (mirrors engine logic).
fn peer_id_from_pubkey(pubkey: &ed25519_dalek::VerifyingKey) -> libp2p::PeerId {
    let ed_pk = libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey.as_bytes()).unwrap();
    let libp2p_pk = libp2p::identity::PublicKey::from(ed_pk);
    libp2p::PeerId::from(libp2p_pk)
}

// ───────────────────────────────────────────────────────────────────────────
// 1 & 2. Private message send/receive with tags + FTS5 search
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn private_message_send_receive_with_tags_and_search() {
    let (mut swarm_a, mut swarm_b, id_a, id_b) = connect_two_swarms().await;

    let b64 = base64::engine::general_purpose::STANDARD;
    let kp_a = id_a.keypair().clone();
    let kp_b = id_b.keypair().clone();
    let pubkey_b = kp_b.verifying_key();
    let peer_b = peer_id_from_pubkey(&pubkey_b);

    // --- Sender (A) encrypts and sends a private message to B ---
    let body_text = "Hello from peer A, this is a secret message!";
    let tags = vec!["urgent".to_string(), "project-alpha".to_string()];

    let shared_secret = ecdh::derive_shared_secret(&kp_a, &pubkey_b);
    let encrypted_payload = ecdh::seal_for(&kp_a, &pubkey_b, body_text.as_bytes()).unwrap();
    let encrypted_tags: Vec<String> = tags
        .iter()
        .map(|tag| {
            let ct = encryption::seal(shared_secret.as_bytes(), tag.as_bytes()).unwrap();
            b64.encode(&ct)
        })
        .collect();

    let mut envelope = Envelope::new(
        kp_a.verifying_key().to_bytes(),
        "dm".into(),
        encrypted_payload,
    );
    envelope.recipient = Some(peer_b);
    envelope.tags = encrypted_tags;
    let original_id = envelope.id;

    let encoded = codec::encode(&envelope, &kp_a).unwrap();

    // Send via request-response.
    swarm_a
        .behaviour_mut()
        .mail_rr
        .send_request(&peer_b, MailRequest { envelope_data: encoded.clone() });

    // --- Receiver (B) handles the request and decrypts ---
    let store_b = MessageStore::open_memory().unwrap();

    let timeout = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut message_received = false;

    while !message_received {
        if tokio::time::Instant::now() > timeout {
            panic!("timeout waiting for mail request on swarm B");
        }
        tokio::select! {
            event = swarm_b.select_next_some() => {
                if let SwarmEvent::Behaviour(SlashmailBehaviourEvent::MailRr(
                    RrEvent::Message {
                        message: RrMessage::Request { request, channel, .. },
                        ..
                    },
                )) = event
                {
                    // Decode the envelope.
                    let decoded = codec::decode(&request.envelope_data).unwrap();
                    assert_eq!(decoded.id, original_id);
                    assert!(decoded.recipient.is_some());

                    // Verify signature.
                    let sender_pubkey = ed25519_dalek::VerifyingKey::from_bytes(&decoded.sender_pubkey).unwrap();
                    let sig = ed25519_dalek::Signature::from_slice(&decoded.signature).unwrap();
                    slashmail::crypto::signing::verify(&sender_pubkey, &decoded.signable_bytes(), &sig).unwrap();

                    // Decrypt body.
                    let plaintext = ecdh::open_from(&kp_b, &sender_pubkey, &decoded.payload).unwrap();
                    let body = String::from_utf8(plaintext).unwrap();
                    assert_eq!(body, body_text);

                    // Decrypt tags.
                    let shared = ecdh::derive_shared_secret(&kp_b, &sender_pubkey);
                    let mut decrypted_tags = Vec::new();
                    for enc_tag in &decoded.tags {
                        let tag_bytes = b64.decode(enc_tag).unwrap();
                        let plain = encryption::open(shared.as_bytes(), &tag_bytes).unwrap();
                        decrypted_tags.push(String::from_utf8(plain).unwrap());
                    }
                    assert_eq!(decrypted_tags, tags);

                    // Store message.
                    let msg = Message {
                        id: decoded.id,
                        swarm_id: decoded.swarm_id.clone(),
                        folder_path: "INBOX".into(),
                        sender_pubkey: decoded.sender_pubkey,
                        sender: b64.encode(decoded.sender_pubkey),
                        recipient: decoded.recipient.map(|p| p.to_string()).unwrap_or_default(),
                        subject: String::new(),
                        body: body.clone(),
                        tags: decrypted_tags.join(" "),
                        created_at: decoded.timestamp,
                        read: false,
                    };
                    store_b.insert_message(&msg).unwrap();
                    store_b.store_raw_envelope(&decoded.id, &request.envelope_data).unwrap();
                    let tag_refs: Vec<&str> = decrypted_tags.iter().map(|s| s.as_str()).collect();
                    store_b.upsert_tags(&decoded.id, &tag_refs).unwrap();

                    // Send acceptance response.
                    swarm_b
                        .behaviour_mut()
                        .mail_rr
                        .send_response(channel, MailResponse::accepted())
                        .expect("send response should succeed");

                    message_received = true;
                }
            }
            _ = swarm_a.select_next_some() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    // --- Verify stored message ---
    let messages = store_b.list_messages(0).unwrap();
    assert_eq!(messages.len(), 1);
    let stored = &messages[0];
    assert_eq!(stored.id, original_id);
    assert_eq!(stored.swarm_id, "dm");
    assert_eq!(stored.folder_path, "INBOX");
    assert_eq!(stored.body, body_text);
    // Tags are space-separated; verify both are present regardless of order.
    let stored_tags: Vec<&str> = stored.tags.split_whitespace().collect();
    assert!(stored_tags.contains(&"urgent"));
    assert!(stored_tags.contains(&"project-alpha"));
    assert_eq!(stored_tags.len(), 2);
    assert!(!stored.read);

    // --- FTS5 search by body ---
    let results = store_b.search_messages("secret message").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, original_id);

    // --- FTS5 search by tag ---
    let results = store_b.search_messages("urgent").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, original_id);

    // --- Tag query ---
    let by_tag = store_b.messages_by_tag("project-alpha").unwrap();
    assert_eq!(by_tag.len(), 1);
    assert_eq!(by_tag[0].id, original_id);
}

// ───────────────────────────────────────────────────────────────────────────
// 3. Delta-sync of 3 messages to a late-joining peer
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn delta_sync_three_messages_to_late_joiner() {
    let b64 = base64::engine::general_purpose::STANDARD;
    let kp_a = generate_keypair();
    let kp_b = generate_keypair();
    let pubkey_a = kp_a.verifying_key();
    let pubkey_b = kp_b.verifying_key();

    // --- Peer A: store 3 messages with raw envelopes ---
    let store_a = MessageStore::open_memory().unwrap();
    let mut message_ids = Vec::new();

    for i in 0..3 {
        let body = format!("sync message {i}");
        let tags = vec![format!("tag-{i}")];

        // Encrypt body and tags as private messages from A to B.
        let shared = ecdh::derive_shared_secret(&kp_a, &pubkey_b);
        let encrypted_payload = ecdh::seal_for(&kp_a, &pubkey_b, body.as_bytes()).unwrap();
        let encrypted_tags: Vec<String> = tags
            .iter()
            .map(|tag| {
                let ct = encryption::seal(shared.as_bytes(), tag.as_bytes()).unwrap();
                b64.encode(&ct)
            })
            .collect();

        let mut envelope = Envelope::new(
            pubkey_a.to_bytes(),
            "dm".into(),
            encrypted_payload,
        );
        envelope.recipient = Some(peer_id_from_pubkey(&pubkey_b));
        envelope.tags = encrypted_tags;

        let encoded = codec::encode(&envelope, &kp_a).unwrap();
        let msg_id = envelope.id;
        message_ids.push(msg_id);

        // Store in A's database (Sent folder with plaintext body/tags).
        let msg = Message {
            id: msg_id,
            swarm_id: "dm".into(),
            folder_path: "Sent".into(),
            sender_pubkey: pubkey_a.to_bytes(),
            sender: b64.encode(pubkey_a.to_bytes()),
            recipient: peer_id_from_pubkey(&pubkey_b).to_string(),
            subject: String::new(),
            body: body.clone(),
            tags: tags.join(" "),
            created_at: envelope.timestamp,
            read: true,
        };
        store_a.insert_message(&msg).unwrap();
        store_a.store_raw_envelope(&msg_id, &encoded).unwrap();
        let tag_refs: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
        store_a.upsert_tags(&msg_id, &tag_refs).unwrap();
    }

    // Verify A has 3 messages.
    let a_ids = store_a.all_message_ids().unwrap();
    assert_eq!(a_ids.len(), 3);

    // --- Peer B: empty store, late joiner ---
    let store_b = MessageStore::open_memory().unwrap();
    assert_eq!(store_b.all_message_ids().unwrap().len(), 0);

    // --- Connect two swarms ---
    let (mut swarm_a, mut swarm_b, _id_a, _id_b) = connect_two_swarms().await;
    let peer_a = *swarm_a.local_peer_id();

    // --- Step 1: B sends RootExchange to A ---
    let b_ids = store_b.all_message_ids().unwrap();
    let b_tree = MerkleTree::from_ids(&b_ids);

    swarm_b.behaviour_mut().sync_rr.send_request(
        &peer_a,
        SyncRequest::RootExchange { root: *b_tree.root() },
    );

    // Poll until A receives the request and B gets the RootResult response.
    let timeout = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut differing_buckets: Option<Vec<u16>> = None;

    while differing_buckets.is_none() {
        if tokio::time::Instant::now() > timeout {
            panic!("timeout waiting for sync RootResult");
        }
        tokio::select! {
            event = swarm_a.select_next_some() => {
                // Handle A's side: respond to sync requests.
                if let SwarmEvent::Behaviour(SlashmailBehaviourEvent::SyncRr(
                    RrEvent::Message {
                        message: RrMessage::Request { request, channel, .. },
                        ..
                    },
                )) = event
                {
                    match request {
                        SyncRequest::RootExchange { .. } => {
                            let ids = store_a.all_message_ids().unwrap();
                            let tree = MerkleTree::from_ids(&ids);
                            swarm_a.behaviour_mut().sync_rr.send_response(
                                channel,
                                SyncResponse::RootResult {
                                    root: *tree.root(),
                                    bucket_hashes: tree.bucket_hashes().to_vec(),
                                },
                            ).expect("send sync response");
                        }
                        _ => panic!("unexpected sync request in step 1"),
                    }
                }
            }
            event = swarm_b.select_next_some() => {
                // Handle B's side: receive the RootResult response.
                if let SwarmEvent::Behaviour(SlashmailBehaviourEvent::SyncRr(
                    RrEvent::Message {
                        message: RrMessage::Response { response, .. },
                        ..
                    },
                )) = event
                {
                    if let SyncResponse::RootResult { root: remote_root, bucket_hashes } = response {
                        let local_tree = MerkleTree::from_ids(&store_b.all_message_ids().unwrap());
                        assert_ne!(*local_tree.root(), remote_root, "roots should differ");
                        let diff = local_tree.differing_buckets(&bucket_hashes);
                        assert!(!diff.is_empty(), "should have differing buckets");
                        differing_buckets = Some(diff);
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    // --- Step 2: B requests bucket IDs for differing buckets ---
    let diff_buckets = differing_buckets.unwrap();
    swarm_b.behaviour_mut().sync_rr.send_request(
        &peer_a,
        SyncRequest::GetBucketIds { bucket_indices: diff_buckets },
    );

    let mut missing_ids: Option<Vec<String>> = None;

    let timeout = tokio::time::Instant::now() + Duration::from_secs(10);
    while missing_ids.is_none() {
        if tokio::time::Instant::now() > timeout {
            panic!("timeout waiting for sync BucketIds");
        }
        tokio::select! {
            event = swarm_a.select_next_some() => {
                if let SwarmEvent::Behaviour(SlashmailBehaviourEvent::SyncRr(
                    RrEvent::Message {
                        message: RrMessage::Request { request, channel, .. },
                        ..
                    },
                )) = event
                {
                    if let SyncRequest::GetBucketIds { bucket_indices } = request {
                        let ids = store_a.all_message_ids().unwrap();
                        let tree = MerkleTree::from_ids(&ids);
                        let buckets: Vec<(u16, Vec<String>)> = bucket_indices
                            .iter()
                            .map(|&idx| {
                                let ids: Vec<String> = tree
                                    .bucket_ids(idx as usize)
                                    .iter()
                                    .map(|id| id.to_string())
                                    .collect();
                                (idx, ids)
                            })
                            .collect();
                        swarm_a.behaviour_mut().sync_rr.send_response(
                            channel,
                            SyncResponse::BucketIds { buckets },
                        ).expect("send bucket ids response");
                    }
                }
            }
            event = swarm_b.select_next_some() => {
                if let SwarmEvent::Behaviour(SlashmailBehaviourEvent::SyncRr(
                    RrEvent::Message {
                        message: RrMessage::Response { response, .. },
                        ..
                    },
                )) = event
                {
                    if let SyncResponse::BucketIds { buckets } = response {
                        let local_tree = MerkleTree::from_ids(&store_b.all_message_ids().unwrap());
                        let remote_bucket_ids: Vec<(u16, Vec<uuid::Uuid>)> = buckets
                            .iter()
                            .map(|(idx, id_strings)| {
                                let uuids: Vec<uuid::Uuid> = id_strings
                                    .iter()
                                    .filter_map(|s| uuid::Uuid::parse_str(s).ok())
                                    .collect();
                                (*idx, uuids)
                            })
                            .collect();
                        let missing = local_tree.missing_ids(&remote_bucket_ids);
                        assert_eq!(missing.len(), 3, "should be missing all 3 messages");
                        missing_ids = Some(missing.iter().map(|id| id.to_string()).collect());
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    // --- Step 3: B fetches the missing messages ---
    let fetch_ids = missing_ids.unwrap();
    swarm_b.behaviour_mut().sync_rr.send_request(
        &peer_a,
        SyncRequest::FetchMessages { ids: fetch_ids },
    );

    let timeout = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut sync_complete = false;

    while !sync_complete {
        if tokio::time::Instant::now() > timeout {
            panic!("timeout waiting for sync FetchMessages response");
        }
        tokio::select! {
            event = swarm_a.select_next_some() => {
                if let SwarmEvent::Behaviour(SlashmailBehaviourEvent::SyncRr(
                    RrEvent::Message {
                        message: RrMessage::Request { request, channel, .. },
                        ..
                    },
                )) = event
                {
                    if let SyncRequest::FetchMessages { ids } = request {
                        let envelopes = store_a.get_raw_envelopes(&ids).unwrap();
                        assert_eq!(envelopes.len(), 3, "A should return all 3 raw envelopes");
                        swarm_a.behaviour_mut().sync_rr.send_response(
                            channel,
                            SyncResponse::Messages { envelopes },
                        ).expect("send messages response");
                    }
                }
            }
            event = swarm_b.select_next_some() => {
                if let SwarmEvent::Behaviour(SlashmailBehaviourEvent::SyncRr(
                    RrEvent::Message {
                        message: RrMessage::Response { response, .. },
                        ..
                    },
                )) = event
                {
                    if let SyncResponse::Messages { envelopes } = response {
                        assert_eq!(envelopes.len(), 3);

                        // Process each envelope: decode, verify, decrypt, store.
                        for (_id_str, raw_data) in &envelopes {
                            let decoded = codec::decode(raw_data).unwrap();

                            // Verify signature.
                            let sender_pk = ed25519_dalek::VerifyingKey::from_bytes(&decoded.sender_pubkey).unwrap();
                            let sig = ed25519_dalek::Signature::from_slice(&decoded.signature).unwrap();
                            slashmail::crypto::signing::verify(&sender_pk, &decoded.signable_bytes(), &sig).unwrap();

                            // Decrypt body and tags (private message to B).
                            let plaintext = ecdh::open_from(&kp_b, &sender_pk, &decoded.payload).unwrap();
                            let body = String::from_utf8(plaintext).unwrap();

                            let shared = ecdh::derive_shared_secret(&kp_b, &sender_pk);
                            let mut decrypted_tags = Vec::new();
                            for enc_tag in &decoded.tags {
                                let tag_bytes = b64.decode(enc_tag).unwrap();
                                let plain = encryption::open(shared.as_bytes(), &tag_bytes).unwrap();
                                decrypted_tags.push(String::from_utf8(plain).unwrap());
                            }

                            let msg = Message {
                                id: decoded.id,
                                swarm_id: decoded.swarm_id.clone(),
                                folder_path: "INBOX".into(),
                                sender_pubkey: decoded.sender_pubkey,
                                sender: b64.encode(decoded.sender_pubkey),
                                recipient: decoded.recipient.map(|p| p.to_string()).unwrap_or_default(),
                                subject: String::new(),
                                body,
                                tags: decrypted_tags.join(" "),
                                created_at: decoded.timestamp,
                                read: false,
                            };
                            store_b.insert_message(&msg).unwrap();
                            store_b.store_raw_envelope(&decoded.id, raw_data).unwrap();
                            if !decrypted_tags.is_empty() {
                                let tag_refs: Vec<&str> = decrypted_tags.iter().map(|s| s.as_str()).collect();
                                store_b.upsert_tags(&decoded.id, &tag_refs).unwrap();
                            }
                        }

                        sync_complete = true;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    // --- Verify B now has all 3 messages ---
    let b_messages = store_b.list_messages(0).unwrap();
    assert_eq!(b_messages.len(), 3);

    // All original message IDs should be present.
    let b_stored_ids: Vec<Uuid> = b_messages.iter().map(|m| m.id).collect();
    for expected_id in &message_ids {
        assert!(b_stored_ids.contains(expected_id), "missing message {expected_id}");
    }

    // Verify message bodies.
    for i in 0..3 {
        let expected_body = format!("sync message {i}");
        assert!(
            b_messages.iter().any(|m| m.body == expected_body),
            "missing body: {expected_body}"
        );
    }

    // Verify tags.
    for i in 0..3 {
        let expected_tag = format!("tag-{i}");
        let by_tag = store_b.messages_by_tag(&expected_tag).unwrap();
        assert_eq!(by_tag.len(), 1, "tag {expected_tag} should match exactly 1 message");
    }

    // Verify Merkle roots now match.
    let a_ids = store_a.all_message_ids().unwrap();
    let b_ids = store_b.all_message_ids().unwrap();
    let tree_a = MerkleTree::from_ids(&a_ids);
    let tree_b = MerkleTree::from_ids(&b_ids);
    assert_eq!(tree_a.root(), tree_b.root(), "Merkle roots should match after sync");
}
