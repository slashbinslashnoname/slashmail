//! Control socket for daemon IPC.
//!
//! The daemon listens on a Unix domain socket (`~/.slashmail/daemon.sock`).
//! CLI commands connect, send a JSON request, and read a JSON response.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::engine::{EngineCommand, PeerInfo, StatusInfo};
use crate::storage::config::Config;

/// JSON request sent by CLI clients.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum CtlRequest {
    Status,
    AddPeer { addr: String },
    Peers,
    Send {
        to: String,
        body: String,
        tags: Vec<String>,
    },
}

/// JSON response sent back to CLI clients.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CtlResponse {
    Status(StatusInfo),
    AddPeer { ok: bool, error: Option<String> },
    Peers { peers: Vec<PeerInfo> },
    Send {
        ok: bool,
        message_id: Option<String>,
        error: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        warning: Option<String>,
    },
    Error { message: String },
}

/// Return the path to the daemon control socket.
pub fn socket_path() -> Result<PathBuf> {
    Ok(Config::data_dir()?.join("daemon.sock"))
}

/// Start the control socket server. Spawns a tokio task that accepts
/// connections and dispatches commands to the engine via `cmd_tx`.
///
/// Removes any stale socket file before binding.
pub async fn serve(sock_path: &Path, cmd_tx: mpsc::Sender<EngineCommand>) -> Result<()> {
    // Remove stale socket if present.
    if sock_path.exists() {
        std::fs::remove_file(sock_path)
            .with_context(|| format!("failed to remove stale socket: {}", sock_path.display()))?;
    }

    let listener = UnixListener::bind(sock_path)
        .with_context(|| format!("failed to bind control socket: {}", sock_path.display()))?;

    info!(path = %sock_path.display(), "control socket listening");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let tx = cmd_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, tx).await {
                            warn!(%e, "control socket connection error");
                        }
                    });
                }
                Err(e) => {
                    warn!(%e, "control socket accept error");
                }
            }
        }
    });

    Ok(())
}

/// Handle a single control socket connection: read one JSON line, dispatch, respond.
async fn handle_connection(stream: UnixStream, cmd_tx: mpsc::Sender<EngineCommand>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    if let Some(line) = lines.next_line().await? {
        debug!(request = %line, "control request");
        let response = match serde_json::from_str::<CtlRequest>(&line) {
            Ok(req) => dispatch(req, &cmd_tx).await,
            Err(e) => CtlResponse::Error {
                message: format!("invalid request: {e}"),
            },
        };
        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
    }
    Ok(())
}

/// Dispatch a control request to the engine and await the response.
async fn dispatch(req: CtlRequest, cmd_tx: &mpsc::Sender<EngineCommand>) -> CtlResponse {
    match req {
        CtlRequest::Status => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if cmd_tx
                .send(EngineCommand::GetStatus { reply: reply_tx })
                .await
                .is_err()
            {
                return CtlResponse::Error {
                    message: "engine channel closed".into(),
                };
            }
            match reply_rx.await {
                Ok(info) => CtlResponse::Status(info),
                Err(_) => CtlResponse::Error {
                    message: "engine did not respond".into(),
                },
            }
        }
        CtlRequest::AddPeer { addr } => {
            let parsed: Multiaddr = match addr.parse() {
                Ok(a) => a,
                Err(e) => {
                    return CtlResponse::AddPeer {
                        ok: false,
                        error: Some(format!("invalid multiaddr: {e}")),
                    }
                }
            };
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if cmd_tx
                .send(EngineCommand::AddPeer {
                    addr: parsed,
                    reply: reply_tx,
                })
                .await
                .is_err()
            {
                return CtlResponse::Error {
                    message: "engine channel closed".into(),
                };
            }
            match reply_rx.await {
                Ok(Ok(())) => CtlResponse::AddPeer {
                    ok: true,
                    error: None,
                },
                Ok(Err(e)) => CtlResponse::AddPeer {
                    ok: false,
                    error: Some(e),
                },
                Err(_) => CtlResponse::Error {
                    message: "engine did not respond".into(),
                },
            }
        }
        CtlRequest::Peers => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if cmd_tx
                .send(EngineCommand::GetPeers { reply: reply_tx })
                .await
                .is_err()
            {
                return CtlResponse::Error {
                    message: "engine channel closed".into(),
                };
            }
            match reply_rx.await {
                Ok(peers) => CtlResponse::Peers { peers },
                Err(_) => CtlResponse::Error {
                    message: "engine did not respond".into(),
                },
            }
        }
        CtlRequest::Send { to, body, tags } => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if cmd_tx
                .send(EngineCommand::SendMessage {
                    to,
                    body,
                    tags,
                    reply: reply_tx,
                })
                .await
                .is_err()
            {
                return CtlResponse::Error {
                    message: "engine channel closed".into(),
                };
            }
            match reply_rx.await {
                Ok(Ok((message_id, warning))) => CtlResponse::Send {
                    ok: true,
                    message_id: Some(message_id),
                    error: None,
                    warning,
                },
                Ok(Err(e)) => CtlResponse::Send {
                    ok: false,
                    message_id: None,
                    error: Some(e),
                    warning: None,
                },
                Err(_) => CtlResponse::Error {
                    message: "engine did not respond".into(),
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Client helpers (used by CLI commands to talk to a running daemon)
// ---------------------------------------------------------------------------

/// Send a control request to the daemon and return the parsed response.
pub async fn send_request(req: &CtlRequest) -> Result<CtlResponse> {
    let sock = socket_path()?;
    let stream = UnixStream::connect(&sock)
        .await
        .with_context(|| {
            format!(
                "could not connect to daemon at {} — is it running?",
                sock.display()
            )
        })?;

    let (reader, mut writer) = stream.into_split();
    let mut json = serde_json::to_string(req)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.shutdown().await?;

    let mut lines = BufReader::new(reader).lines();
    let line = lines
        .next_line()
        .await?
        .context("daemon closed connection without responding")?;
    let resp: CtlResponse = serde_json::from_str(&line)?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serialization_roundtrip() {
        let req = CtlRequest::AddPeer {
            addr: "/ip4/1.2.3.4/tcp/4001".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CtlRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            CtlRequest::AddPeer { addr } => assert_eq!(addr, "/ip4/1.2.3.4/tcp/4001"),
            _ => panic!("expected AddPeer"),
        }
    }

    #[test]
    fn response_serialization_roundtrip() {
        let resp = CtlResponse::Status(StatusInfo {
            peer_id: "12D3KooW...".into(),
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/4001".into()],
            external_addrs: vec![],
            num_peers: 3,
        });
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: CtlResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            CtlResponse::Status(info) => {
                assert_eq!(info.num_peers, 3);
                assert_eq!(info.listen_addrs.len(), 1);
            }
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn peers_response_roundtrip() {
        let resp = CtlResponse::Peers {
            peers: vec![PeerInfo {
                peer_id: "12D3KooW...".into(),
                addrs: vec!["/ip4/1.2.3.4/tcp/4001".into()],
                connected_since: "2026-01-01T00:00:00Z".into(),
                protocols: vec!["/slashmail/mail/1.0.0".into()],
                rtt_ms: Some(12.5),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: CtlResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            CtlResponse::Peers { peers } => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].rtt_ms, Some(12.5));
            }
            _ => panic!("expected Peers"),
        }
    }

    #[test]
    fn send_request_serialization_roundtrip() {
        let req = CtlRequest::Send {
            to: "AAAA".into(),
            body: "hello world".into(),
            tags: vec!["inbox".into(), "urgent".into()],
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CtlRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            CtlRequest::Send { to, body, tags } => {
                assert_eq!(to, "AAAA");
                assert_eq!(body, "hello world");
                assert_eq!(tags, vec!["inbox", "urgent"]);
            }
            _ => panic!("expected Send"),
        }
    }

    #[test]
    fn send_response_ok_roundtrip() {
        let resp = CtlResponse::Send {
            ok: true,
            message_id: Some("abc-123".into()),
            error: None,
            warning: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: CtlResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            CtlResponse::Send {
                ok,
                message_id,
                error,
                ..
            } => {
                assert!(ok);
                assert_eq!(message_id.as_deref(), Some("abc-123"));
                assert!(error.is_none());
            }
            _ => panic!("expected Send"),
        }
    }

    #[test]
    fn send_response_err_roundtrip() {
        let resp = CtlResponse::Send {
            ok: false,
            message_id: None,
            error: Some("bad key".into()),
            warning: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: CtlResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            CtlResponse::Send { ok, error, .. } => {
                assert!(!ok);
                assert_eq!(error.as_deref(), Some("bad key"));
            }
            _ => panic!("expected Send"),
        }
    }

    #[tokio::test]
    async fn server_and_client_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let sock = tmp.path().join("test.sock");

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<EngineCommand>(16);

        serve(&sock, cmd_tx).await.unwrap();

        // Spawn a fake engine that handles GetStatus.
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    EngineCommand::GetStatus { reply } => {
                        let _ = reply.send(StatusInfo {
                            peer_id: "test-peer-id".into(),
                            listen_addrs: vec![],
                            external_addrs: vec![],
                            num_peers: 0,
                        });
                    }
                    _ => {}
                }
            }
        });

        // Client connects and sends status request.
        let stream = UnixStream::connect(&sock).await.unwrap();
        let (reader, mut writer) = stream.into_split();

        let req = serde_json::to_string(&CtlRequest::Status).unwrap() + "\n";
        writer.write_all(req.as_bytes()).await.unwrap();
        writer.shutdown().await.unwrap();

        let mut lines = BufReader::new(reader).lines();
        let line = lines.next_line().await.unwrap().unwrap();
        let resp: CtlResponse = serde_json::from_str(&line).unwrap();

        match resp {
            CtlResponse::Status(info) => {
                assert_eq!(info.peer_id, "test-peer-id");
            }
            other => panic!("expected Status, got: {other:?}"),
        }
    }
}
