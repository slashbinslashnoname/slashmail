//! Cryptographic primitives: signing (Ed25519), encryption (XChaCha20-Poly1305),
//! and ECDH key derivation (Ed25519→X25519).

pub mod signing;
pub mod encryption;
pub mod ecdh;

pub use signing::{Keypair, PublicKey, Signature};
pub use encryption::{seal, open, generate_nonce};
pub use ecdh::{derive_shared_secret, seal_for, open_from, SharedSecret};
