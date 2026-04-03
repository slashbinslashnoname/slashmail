//! Networking layer: libp2p transport, behaviour, and swarm construction.

pub mod behaviour;
pub mod transport;

use crate::error::AppError;
use crate::identity::Identity;
use behaviour::SlashmailBehaviour;
use libp2p::{PeerId, Swarm, SwarmBuilder};

/// Convert an ed25519-dalek signing key to a libp2p identity keypair.
///
/// Both use the same Ed25519 curve, so we can transfer the raw 32-byte
/// secret seed directly.
pub fn convert_keypair(identity: &Identity) -> Result<libp2p::identity::Keypair, AppError> {
    let secret_bytes = identity.keypair().to_bytes();
    let public_bytes = identity.public_key().to_bytes();
    // libp2p expects a 64-byte array: 32 bytes secret seed || 32 bytes public key.
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&secret_bytes);
    combined[32..].copy_from_slice(&public_bytes);
    let ed25519_keypair = libp2p::identity::ed25519::Keypair::try_from_bytes(&mut combined)
        .map_err(|e| AppError::Network(format!("failed to convert keypair: {e}")))?;
    Ok(libp2p::identity::Keypair::from(ed25519_keypair))
}

/// Build a fully configured libp2p [`Swarm`] with QUIC primary and TCP fallback.
///
/// QUIC is attempted first (UDP-based, better for dcutr NAT hole-punching).
/// TCP+Noise+Yamux is used as fallback when UDP is unavailable.
/// Returns the swarm and its local PeerId.
pub async fn build_swarm(
    identity: &Identity,
) -> Result<(Swarm<SlashmailBehaviour>, PeerId), AppError> {
    let keypair = convert_keypair(identity)?;
    let peer_id = PeerId::from(keypair.public());

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| AppError::Network(format!("TCP transport setup failed: {e}")))?
        .with_quic()
        .with_dns()
        .map_err(|e| AppError::Network(format!("DNS transport setup failed: {e}")))?
        .with_behaviour(|key| {
            behaviour::SlashmailBehaviour::new(key)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        })
        .map_err(|e| AppError::Network(format!("behaviour setup failed: {e}")))?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(std::time::Duration::from_secs(60))
        })
        .build();

    Ok((swarm, peer_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_keypair_preserves_public_key() {
        let identity = Identity::generate();
        let dalek_pk = identity.public_key();

        let libp2p_keypair = convert_keypair(&identity).unwrap();
        let libp2p_pk_bytes = libp2p_keypair
            .public()
            .try_into_ed25519()
            .expect("should be ed25519")
            .to_bytes();

        assert_eq!(dalek_pk.as_bytes(), &libp2p_pk_bytes);
    }

    #[test]
    fn convert_keypair_deterministic() {
        let identity = Identity::generate();
        let kp1 = convert_keypair(&identity).unwrap();
        let kp2 = convert_keypair(&identity).unwrap();
        assert_eq!(kp1.public().to_peer_id(), kp2.public().to_peer_id());
    }

    #[test]
    fn convert_keypair_preserves_signing_capability() {
        use ed25519_dalek::Verifier;

        let identity = Identity::generate();
        let libp2p_keypair = convert_keypair(&identity).unwrap();

        // Sign with the libp2p ed25519 keypair.
        let msg = b"slashmail test message";
        let libp2p_ed25519 = libp2p_keypair
            .try_into_ed25519()
            .expect("should be ed25519");
        let sig_bytes = libp2p_ed25519.sign(msg);

        // Verify with the original dalek public key — proves secret key was preserved.
        let dalek_pk = identity.public_key();
        let sig_array: [u8; 64] = sig_bytes.try_into().expect("signature must be 64 bytes");
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_array);
        assert!(
            dalek_pk.verify(msg, &dalek_sig).is_ok(),
            "signature from converted keypair must verify with original dalek public key"
        );
    }

    #[tokio::test]
    async fn build_swarm_starts() {
        let identity = Identity::generate();
        let result = build_swarm(&identity).await;
        assert!(result.is_ok(), "swarm should build successfully");
        let (swarm, peer_id) = result.unwrap();
        assert_eq!(*swarm.local_peer_id(), peer_id);
    }

    #[tokio::test]
    async fn build_swarm_peer_id_matches_identity() {
        let identity = Identity::generate();
        let keypair = convert_keypair(&identity).unwrap();
        let expected_peer_id = PeerId::from(keypair.public());
        let (_swarm, peer_id) = build_swarm(&identity).await.unwrap();
        assert_eq!(peer_id, expected_peer_id);
    }
}
