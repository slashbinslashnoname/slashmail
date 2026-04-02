//! Cryptographic primitives: signing (Ed25519) and encryption (XChaCha20-Poly1305).

pub mod signing;
pub mod encryption;

pub use signing::{Keypair, PublicKey, Signature};
pub use encryption::{seal, open, generate_nonce};
