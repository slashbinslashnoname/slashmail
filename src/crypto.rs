//! Cryptographic primitives: signing (ed25519) and encryption (ChaCha20-Poly1305).

pub mod signing;
pub mod encrypt;

pub use signing::{Keypair, PublicKey, Signature};
pub use encrypt::{seal, open};
