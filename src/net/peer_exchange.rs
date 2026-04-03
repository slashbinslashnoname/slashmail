//! Request-response protocol for exchanging known peer multiaddresses.
//!
//! When a connection is established, both sides exchange their routing tables
//! (known PeerIds and their observed multiaddresses) so that each node can
//! expand its mesh by dialing newly discovered peers.
//!
//! Uses the same length-prefixed bincode wire format as the mail protocol.
//! Protocol ID: `/slashmail/peer-exchange/1.0.0`

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::io;

/// Protocol identifier for peer exchange.
pub const PROTOCOL_NAME: &str = "/slashmail/peer-exchange/1.0.0";

/// Maximum message size (256 KiB). Peer tables are much smaller than mail
/// envelopes, but we allow headroom for large meshes.
const MAX_MESSAGE_SIZE: u32 = 262_144;

/// A single peer entry: a PeerId and its known multiaddresses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfo {
    /// The peer's libp2p identity, serialized as bytes.
    pub peer_id: Vec<u8>,
    /// Known multiaddresses for this peer, serialized as byte vectors.
    pub addrs: Vec<Vec<u8>>,
}

/// Request sent to a newly connected peer with our known routing table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerExchangeRequest {
    pub peers: Vec<PeerInfo>,
}

/// Response containing the remote peer's known routing table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerExchangeResponse {
    pub peers: Vec<PeerInfo>,
}

/// Convert a `(PeerId, Vec<Multiaddr>)` pair into a wire-safe `PeerInfo`.
pub fn to_peer_info(peer_id: &PeerId, addrs: &[Multiaddr]) -> PeerInfo {
    PeerInfo {
        peer_id: peer_id.to_bytes(),
        addrs: addrs.iter().map(|a| a.to_vec()).collect(),
    }
}

/// Parse a `PeerInfo` back into `(PeerId, Vec<Multiaddr>)`.
/// Returns `None` if the peer ID or any address is malformed.
pub fn from_peer_info(info: &PeerInfo) -> Option<(PeerId, Vec<Multiaddr>)> {
    let peer_id = PeerId::from_bytes(&info.peer_id).ok()?;
    let addrs: Option<Vec<Multiaddr>> = info
        .addrs
        .iter()
        .map(|a| Multiaddr::try_from(a.clone()).ok())
        .collect();
    Some((peer_id, addrs?))
}

/// Bincode-based codec for the peer exchange protocol.
#[derive(Debug, Clone, Default)]
pub struct PeerExchangeCodec;

impl PeerExchangeCodec {
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
impl request_response::Codec for PeerExchangeCodec {
    type Protocol = String;
    type Request = PeerExchangeRequest;
    type Response = PeerExchangeResponse;

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

/// Create a new request-response [`Behaviour`] for the peer exchange protocol.
pub fn peer_exchange_behaviour() -> request_response::Behaviour<PeerExchangeCodec> {
    request_response::Behaviour::with_codec(
        PeerExchangeCodec,
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
    fn peer_info_roundtrip() {
        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/9000".parse().unwrap();
        let info = to_peer_info(&peer_id, &[addr.clone()]);
        let (parsed_id, parsed_addrs) = from_peer_info(&info).unwrap();
        assert_eq!(parsed_id, peer_id);
        assert_eq!(parsed_addrs, vec![addr]);
    }

    #[test]
    fn peer_info_multiple_addrs() {
        let peer_id = PeerId::random();
        let addrs: Vec<Multiaddr> = vec![
            "/ip4/10.0.0.1/tcp/4001".parse().unwrap(),
            "/ip4/10.0.0.1/udp/4001/quic-v1".parse().unwrap(),
        ];
        let info = to_peer_info(&peer_id, &addrs);
        let (parsed_id, parsed_addrs) = from_peer_info(&info).unwrap();
        assert_eq!(parsed_id, peer_id);
        assert_eq!(parsed_addrs, addrs);
    }

    #[test]
    fn peer_info_empty_addrs() {
        let peer_id = PeerId::random();
        let info = to_peer_info(&peer_id, &[]);
        let (parsed_id, parsed_addrs) = from_peer_info(&info).unwrap();
        assert_eq!(parsed_id, peer_id);
        assert!(parsed_addrs.is_empty());
    }

    #[test]
    fn peer_info_invalid_peer_id() {
        let info = PeerInfo {
            peer_id: vec![0xFF, 0xFF],
            addrs: vec![],
        };
        assert!(from_peer_info(&info).is_none());
    }

    #[test]
    fn peer_info_invalid_addr() {
        let peer_id = PeerId::random();
        let info = PeerInfo {
            peer_id: peer_id.to_bytes(),
            addrs: vec![vec![0xFF, 0xFF, 0xFF]],
        };
        assert!(from_peer_info(&info).is_none());
    }

    #[test]
    fn request_bincode_roundtrip() {
        let peer_id = PeerId::random();
        let info = to_peer_info(&peer_id, &["/ip4/1.2.3.4/tcp/80".parse().unwrap()]);
        let req = PeerExchangeRequest {
            peers: vec![info],
        };
        let encoded = bincode::serialize(&req).unwrap();
        let decoded: PeerExchangeRequest = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn response_bincode_roundtrip() {
        let resp = PeerExchangeResponse { peers: vec![] };
        let encoded = bincode::serialize(&resp).unwrap();
        let decoded: PeerExchangeResponse = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    async fn write_then_read_request(req: &PeerExchangeRequest) -> PeerExchangeRequest {
        let protocol = PROTOCOL_NAME.to_string();
        let mut buf = vec![];
        PeerExchangeCodec
            .write_request(&protocol, &mut buf, req.clone())
            .await
            .unwrap();
        let mut cursor = Cursor::new(buf);
        PeerExchangeCodec
            .read_request(&protocol, &mut cursor)
            .await
            .unwrap()
    }

    async fn write_then_read_response(resp: &PeerExchangeResponse) -> PeerExchangeResponse {
        let protocol = PROTOCOL_NAME.to_string();
        let mut buf = vec![];
        PeerExchangeCodec
            .write_response(&protocol, &mut buf, resp.clone())
            .await
            .unwrap();
        let mut cursor = Cursor::new(buf);
        PeerExchangeCodec
            .read_response(&protocol, &mut cursor)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn codec_request_roundtrip() {
        let peer_id = PeerId::random();
        let info = to_peer_info(&peer_id, &["/ip4/1.2.3.4/tcp/80".parse().unwrap()]);
        let req = PeerExchangeRequest {
            peers: vec![info],
        };
        assert_eq!(write_then_read_request(&req).await, req);
    }

    #[tokio::test]
    async fn codec_response_roundtrip() {
        let resp = PeerExchangeResponse {
            peers: vec![to_peer_info(
                &PeerId::random(),
                &["/ip4/10.0.0.1/tcp/4001".parse().unwrap()],
            )],
        };
        assert_eq!(write_then_read_response(&resp).await, resp);
    }

    #[tokio::test]
    async fn codec_empty_peers_roundtrip() {
        let req = PeerExchangeRequest { peers: vec![] };
        assert_eq!(write_then_read_request(&req).await, req);

        let resp = PeerExchangeResponse { peers: vec![] };
        assert_eq!(write_then_read_response(&resp).await, resp);
    }

    #[tokio::test]
    async fn codec_rejects_oversized_message() {
        let protocol = PROTOCOL_NAME.to_string();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_MESSAGE_SIZE + 1).to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]);

        let mut cursor = Cursor::new(buf);
        let err = PeerExchangeCodec
            .read_request(&protocol, &mut cursor)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("message too large"));
    }

    #[tokio::test]
    async fn codec_read_truncated_fails() {
        let protocol = PROTOCOL_NAME.to_string();
        let mut buf = Vec::new();
        buf.extend_from_slice(&16u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 4]); // only 4 of 16 bytes

        let mut cursor = Cursor::new(buf);
        let result: io::Result<PeerExchangeRequest> =
            PeerExchangeCodec.read_request(&protocol, &mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn codec_read_empty_fails() {
        let protocol = PROTOCOL_NAME.to_string();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let result: io::Result<PeerExchangeRequest> =
            PeerExchangeCodec.read_request(&protocol, &mut cursor).await;
        assert!(result.is_err());
    }

    #[test]
    fn peer_exchange_behaviour_creates_successfully() {
        let _behaviour = peer_exchange_behaviour();
    }
}
