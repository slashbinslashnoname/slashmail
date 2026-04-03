//! Request-response protocol for Merkle-tree delta synchronisation.
//!
//! On peer connect the initiator sends its Merkle root. If roots differ the
//! peers walk the tree: exchange bucket hashes, then bucket ID lists, and
//! finally fetch missing messages by ID.
//!
//! Uses the same length-prefixed bincode wire format as the mail and peer
//! exchange protocols.
//! Protocol ID: `/slashmail/sync/1.0.0`

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response;
use serde::{Deserialize, Serialize};
use std::io;

/// Protocol identifier for Merkle sync.
pub const PROTOCOL_NAME: &str = "/slashmail/sync/1.0.0";

/// Maximum message size (4 MiB). Sync payloads can carry many message IDs
/// or raw envelopes.
const MAX_MESSAGE_SIZE: u32 = 4 * 1_048_576;

/// A sync request. The protocol is multi-step: each variant represents one
/// round trip in the reconciliation handshake.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncRequest {
    /// Step 1: "Here is my Merkle root."
    RootExchange {
        root: [u8; 32],
    },
    /// Step 2: "Give me message IDs for these differing buckets."
    GetBucketIds {
        bucket_indices: Vec<u16>,
    },
    /// Step 3: "Send me the raw envelopes for these message IDs."
    FetchMessages {
        ids: Vec<String>,
    },
}

/// A sync response paired with the corresponding request step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncResponse {
    /// Reply to [`SyncRequest::RootExchange`]: our root plus all 256 bucket
    /// hashes so the initiator can immediately identify differing buckets.
    RootResult {
        root: [u8; 32],
        bucket_hashes: Vec<[u8; 32]>,
    },
    /// Reply to [`SyncRequest::GetBucketIds`]: message ID strings per bucket.
    BucketIds {
        buckets: Vec<(u16, Vec<String>)>,
    },
    /// Reply to [`SyncRequest::FetchMessages`]: raw envelope bytes keyed by ID.
    Messages {
        envelopes: Vec<(String, Vec<u8>)>,
    },
}

/// Bincode-based codec for the sync protocol.
#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

impl SyncCodec {
    async fn read_message<T, M>(io: &mut T) -> io::Result<M>
    where
        T: AsyncRead + Unpin + Send,
        M: for<'de> Deserialize<'de>,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("message too large: {len} bytes (max {MAX_MESSAGE_SIZE})"),
            ));
        }
        let mut buf = vec![0u8; len as usize];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_message<T, M>(io: &mut T, msg: &M) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
        M: Serialize,
    {
        let data =
            bincode::serialize(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let len = (data.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&data).await?;
        io.flush().await?;
        Ok(())
    }
}

#[async_trait]
impl request_response::Codec for SyncCodec {
    type Protocol = String;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        Self::read_message(io).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        Self::read_message(io).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Self::write_message(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Self::write_message(io, &res).await
    }
}

/// Create a new request-response [`Behaviour`] for the sync protocol.
pub fn sync_behaviour() -> request_response::Behaviour<SyncCodec> {
    request_response::Behaviour::with_codec(
        SyncCodec,
        [(
            PROTOCOL_NAME.to_string(),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;

    #[test]
    fn root_exchange_bincode_roundtrip() {
        let req = SyncRequest::RootExchange { root: [0xAB; 32] };
        let encoded = bincode::serialize(&req).unwrap();
        let decoded: SyncRequest = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn bucket_ids_bincode_roundtrip() {
        let resp = SyncResponse::BucketIds {
            buckets: vec![
                (0, vec!["id-1".into(), "id-2".into()]),
                (42, vec!["id-3".into()]),
            ],
        };
        let encoded = bincode::serialize(&resp).unwrap();
        let decoded: SyncResponse = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn messages_bincode_roundtrip() {
        let resp = SyncResponse::Messages {
            envelopes: vec![("id-1".into(), vec![1, 2, 3])],
        };
        let encoded = bincode::serialize(&resp).unwrap();
        let decoded: SyncResponse = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    async fn write_then_read_request(req: &SyncRequest) -> SyncRequest {
        let protocol = PROTOCOL_NAME.to_string();
        let mut buf = vec![];
        SyncCodec
            .write_request(&protocol, &mut buf, req.clone())
            .await
            .unwrap();
        let mut cursor = Cursor::new(buf);
        SyncCodec
            .read_request(&protocol, &mut cursor)
            .await
            .unwrap()
    }

    async fn write_then_read_response(resp: &SyncResponse) -> SyncResponse {
        let protocol = PROTOCOL_NAME.to_string();
        let mut buf = vec![];
        SyncCodec
            .write_response(&protocol, &mut buf, resp.clone())
            .await
            .unwrap();
        let mut cursor = Cursor::new(buf);
        SyncCodec
            .read_response(&protocol, &mut cursor)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn codec_root_exchange_roundtrip() {
        let req = SyncRequest::RootExchange { root: [0x42; 32] };
        assert_eq!(write_then_read_request(&req).await, req);
    }

    #[tokio::test]
    async fn codec_get_bucket_ids_roundtrip() {
        let req = SyncRequest::GetBucketIds {
            bucket_indices: vec![0, 1, 255],
        };
        assert_eq!(write_then_read_request(&req).await, req);
    }

    #[tokio::test]
    async fn codec_fetch_messages_roundtrip() {
        let req = SyncRequest::FetchMessages {
            ids: vec!["abc".into(), "def".into()],
        };
        assert_eq!(write_then_read_request(&req).await, req);
    }

    #[tokio::test]
    async fn codec_root_result_roundtrip() {
        let resp = SyncResponse::RootResult {
            root: [0x01; 32],
            bucket_hashes: vec![[0x02; 32]; 256],
        };
        assert_eq!(write_then_read_response(&resp).await, resp);
    }

    #[tokio::test]
    async fn codec_bucket_ids_roundtrip() {
        let resp = SyncResponse::BucketIds {
            buckets: vec![(10, vec!["a".into(), "b".into()])],
        };
        assert_eq!(write_then_read_response(&resp).await, resp);
    }

    #[tokio::test]
    async fn codec_messages_roundtrip() {
        let resp = SyncResponse::Messages {
            envelopes: vec![
                ("id-1".into(), vec![0xDE, 0xAD]),
                ("id-2".into(), vec![0xBE, 0xEF]),
            ],
        };
        assert_eq!(write_then_read_response(&resp).await, resp);
    }

    #[tokio::test]
    async fn codec_rejects_oversized_message() {
        let protocol = PROTOCOL_NAME.to_string();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_MESSAGE_SIZE + 1).to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]);

        let mut cursor = Cursor::new(buf);
        let err = SyncCodec
            .read_request(&protocol, &mut cursor)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("message too large"));
    }

    #[test]
    fn sync_behaviour_creates_successfully() {
        let _behaviour = sync_behaviour();
    }
}
