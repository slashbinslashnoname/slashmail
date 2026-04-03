//! Request-response protocol for direct encrypted message delivery.
//!
//! Uses a length-prefixed bincode wire format over libp2p streams.
//! Protocol ID: `/slashmail/mail/1.0.0`

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response;
use serde::{Deserialize, Serialize};
use std::io;

/// Protocol identifier for private mail delivery.
pub const PROTOCOL_NAME: &str = "/slashmail/mail/1.0.0";

/// Maximum message size (1 MiB). Prevents unbounded allocations from
/// malicious peers.
const MAX_MESSAGE_SIZE: u32 = 1_048_576;

/// Private mail delivery request containing a signed, encoded envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailRequest {
    /// Wire-encoded envelope bytes (version byte + zstd-compressed bincode).
    /// Produced by [`crate::message::codec::encode`].
    pub envelope_data: Vec<u8>,
}

/// Acknowledgement response to a mail delivery request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailResponse {
    /// Whether the recipient accepted the message.
    pub accepted: bool,
    /// Optional reason when the message is rejected.
    pub reason: Option<String>,
}

impl MailResponse {
    /// Create an accepted response.
    pub fn accepted() -> Self {
        Self {
            accepted: true,
            reason: None,
        }
    }

    /// Create a rejected response with a reason.
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            accepted: false,
            reason: Some(reason.into()),
        }
    }
}

/// Bincode-based codec for the mail request-response protocol.
#[derive(Debug, Clone, Default)]
pub struct MailCodec;

impl MailCodec {
    /// Read a length-prefixed bincode message from an async stream.
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

    /// Write a length-prefixed bincode message to an async stream.
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
impl request_response::Codec for MailCodec {
    type Protocol = String;
    type Request = MailRequest;
    type Response = MailResponse;

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

/// Create a new request-response [`Behaviour`] for the mail protocol.
pub fn mail_behaviour() -> request_response::Behaviour<MailCodec> {
    request_response::Behaviour::with_codec(
        MailCodec,
        [(PROTOCOL_NAME.to_string(), request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;

    #[test]
    fn mail_response_accepted() {
        let resp = MailResponse::accepted();
        assert!(resp.accepted);
        assert!(resp.reason.is_none());
    }

    #[test]
    fn mail_response_rejected() {
        let resp = MailResponse::rejected("unknown recipient");
        assert!(!resp.accepted);
        assert_eq!(resp.reason.as_deref(), Some("unknown recipient"));
    }

    #[test]
    fn mail_request_bincode_roundtrip() {
        let req = MailRequest {
            envelope_data: vec![0x01, 0xDE, 0xAD, 0xBE, 0xEF],
        };
        let encoded = bincode::serialize(&req).unwrap();
        let decoded: MailRequest = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn mail_response_bincode_roundtrip() {
        let resp = MailResponse::rejected("bad payload");
        let encoded = bincode::serialize(&resp).unwrap();
        let decoded: MailResponse = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    /// Write to a `Vec<u8>` and read back from a `Cursor` over that buffer.
    async fn write_then_read_request(req: &MailRequest) -> MailRequest {
        let protocol = PROTOCOL_NAME.to_string();
        let mut buf = vec![];
        MailCodec.write_request(&protocol, &mut buf, req.clone()).await.unwrap();
        let mut cursor = Cursor::new(buf);
        MailCodec.read_request(&protocol, &mut cursor).await.unwrap()
    }

    async fn write_then_read_response(resp: &MailResponse) -> MailResponse {
        let protocol = PROTOCOL_NAME.to_string();
        let mut buf = vec![];
        MailCodec.write_response(&protocol, &mut buf, resp.clone()).await.unwrap();
        let mut cursor = Cursor::new(buf);
        MailCodec.read_response(&protocol, &mut cursor).await.unwrap()
    }

    #[tokio::test]
    async fn codec_request_roundtrip() {
        let req = MailRequest {
            envelope_data: vec![0x01, 0x02, 0x03],
        };
        assert_eq!(write_then_read_request(&req).await, req);
    }

    #[tokio::test]
    async fn codec_response_roundtrip() {
        let resp = MailResponse::accepted();
        assert_eq!(write_then_read_response(&resp).await, resp);
    }

    #[tokio::test]
    async fn codec_response_rejected_roundtrip() {
        let resp = MailResponse::rejected("bad payload");
        assert_eq!(write_then_read_response(&resp).await, resp);
    }

    #[tokio::test]
    async fn codec_rejects_oversized_message() {
        let protocol = PROTOCOL_NAME.to_string();

        // Write a length prefix larger than MAX_MESSAGE_SIZE
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_MESSAGE_SIZE + 1).to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]); // dummy payload

        let mut cursor = Cursor::new(buf);
        let err = MailCodec
            .read_request(&protocol, &mut cursor)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("message too large"));
    }

    #[tokio::test]
    async fn codec_request_with_real_envelope() {
        use crate::crypto::signing::generate_keypair;
        use crate::message::codec as msg_codec;
        use crate::types::Envelope;

        let kp = generate_keypair();
        let mut env = Envelope::new(kp.verifying_key().to_bytes(), "dm-swarm".into(), b"hello".to_vec());
        env.tags = vec!["inbox".into()];
        let encoded = msg_codec::encode(&env, &kp).unwrap();

        let req = MailRequest {
            envelope_data: encoded,
        };
        let decoded = write_then_read_request(&req).await;
        assert_eq!(decoded, req);

        // Verify the envelope can be decoded from the request
        let decoded_env = msg_codec::decode(&decoded.envelope_data).unwrap();
        assert_eq!(decoded_env.payload, b"hello");
        assert_eq!(decoded_env.tags, vec!["inbox"]);
    }

    #[test]
    fn mail_behaviour_creates_successfully() {
        let _behaviour = mail_behaviour();
    }

    #[tokio::test]
    async fn codec_read_truncated_fails() {
        let protocol = PROTOCOL_NAME.to_string();

        // Write a valid length prefix but truncate the data
        let mut buf = Vec::new();
        buf.extend_from_slice(&16u32.to_be_bytes()); // says 16 bytes follow
        buf.extend_from_slice(&[0u8; 4]); // but only 4 bytes

        let mut cursor = Cursor::new(buf);
        let result: io::Result<MailRequest> = MailCodec.read_request(&protocol, &mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn codec_read_empty_fails() {
        let protocol = PROTOCOL_NAME.to_string();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let result: io::Result<MailRequest> = MailCodec.read_request(&protocol, &mut cursor).await;
        assert!(result.is_err());
    }
}
