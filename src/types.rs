//! Shared domain types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An encrypted mail envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub id: Uuid,
    pub sender: String,
    pub recipient: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

impl Envelope {
    pub fn new(sender: String, recipient: String, payload: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            id: Uuid::new_v4(),
            sender,
            recipient,
            payload,
            signature,
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_serialization_roundtrip() {
        let env = Envelope::new(
            "alice".into(),
            "bob".into(),
            vec![1, 2, 3],
            vec![4, 5, 6],
        );
        let json = serde_json::to_string(&env).unwrap();
        let parsed: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, env.id);
        assert_eq!(parsed.sender, "alice");
        assert_eq!(parsed.recipient, "bob");
    }
}
