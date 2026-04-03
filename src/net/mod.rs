//! Networking layer: libp2p transport, behaviour, and swarm construction.

pub mod behaviour;
pub mod transport;

use crate::error::AppError;
use crate::identity::Identity;
use behaviour::SlashmailBehaviour;
use libp2p::{Swarm, SwarmBuilder};

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

/// Build a fully configured libp2p [`Swarm`] from an application identity.
///
/// The swarm uses TCP+Noise+Yamux transport and combines Gossipsub, Kademlia,
/// Identify, and mDNS behaviours.
pub async fn build_swarm(identity: &Identity) -> Result<Swarm<SlashmailBehaviour>, AppError> {
    let keypair = convert_keypair(identity)?;

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| AppError::Network(format!("transport setup failed: {e}")))?
        .with_behaviour(|key| {
            behaviour::SlashmailBehaviour::new(key)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        })
        .map_err(|e| AppError::Network(format!("behaviour setup failed: {e}")))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();

    Ok(swarm)
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
        let swarm = build_swarm(&identity).await;
        assert!(swarm.is_ok(), "swarm should build successfully");
    }
}
