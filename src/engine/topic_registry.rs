//! Topic subscription registry mapping gossipsub `TopicHash` values back to
//! human-readable swarm names (e.g. `"pub_general"`).
//!
//! When a gossipsub message arrives it only carries the [`TopicHash`], not the
//! original topic string.  The registry provides the reverse lookup needed for
//! message routing and storage.

use libp2p::gossipsub::TopicHash;
use std::collections::HashMap;

/// Registry that tracks active gossipsub topic subscriptions.
///
/// Maps `TopicHash` → swarm name so that inbound messages can be attributed to
/// the correct swarm without re-hashing every known topic on each message.
#[derive(Debug, Clone, Default)]
pub struct TopicRegistry {
    topics: HashMap<TopicHash, String>,
}

impl TopicRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            topics: HashMap::new(),
        }
    }

    /// Register a topic subscription.
    ///
    /// `swarm_name` is the human-readable name (e.g. `"pub_general"`).
    /// Returns `true` if this is a new subscription, `false` if already present.
    pub fn subscribe(&mut self, swarm_name: &str) -> bool {
        let topic = libp2p::gossipsub::Sha256Topic::new(swarm_name);
        let hash = topic.hash();
        if self.topics.contains_key(&hash) {
            return false;
        }
        self.topics.insert(hash, swarm_name.to_string());
        true
    }

    /// Remove a topic subscription.
    ///
    /// Returns `true` if the topic was present and removed.
    pub fn unsubscribe(&mut self, swarm_name: &str) -> bool {
        let topic = libp2p::gossipsub::Sha256Topic::new(swarm_name);
        self.topics.remove(&topic.hash()).is_some()
    }

    /// Look up the swarm name for a topic hash.
    pub fn resolve(&self, hash: &TopicHash) -> Option<&str> {
        self.topics.get(hash).map(|s| s.as_str())
    }

    /// Return all active subscriptions as `(TopicHash, swarm_name)` pairs.
    pub fn subscriptions(&self) -> &HashMap<TopicHash, String> {
        &self.topics
    }

    /// Number of active subscriptions.
    pub fn len(&self) -> usize {
        self.topics.len()
    }

    /// Whether the registry has no subscriptions.
    pub fn is_empty(&self) -> bool {
        self.topics.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_returns_true_for_new_topic() {
        let mut reg = TopicRegistry::new();
        assert!(reg.subscribe("pub_general"));
    }

    #[test]
    fn subscribe_returns_false_for_duplicate() {
        let mut reg = TopicRegistry::new();
        assert!(reg.subscribe("pub_general"));
        assert!(!reg.subscribe("pub_general"));
    }

    #[test]
    fn unsubscribe_returns_true_when_present() {
        let mut reg = TopicRegistry::new();
        reg.subscribe("pub_general");
        assert!(reg.unsubscribe("pub_general"));
    }

    #[test]
    fn unsubscribe_returns_false_when_absent() {
        let mut reg = TopicRegistry::new();
        assert!(!reg.unsubscribe("pub_general"));
    }

    #[test]
    fn resolve_returns_swarm_name() {
        let mut reg = TopicRegistry::new();
        reg.subscribe("pub_general");
        let topic = libp2p::gossipsub::Sha256Topic::new("pub_general");
        assert_eq!(reg.resolve(&topic.hash()), Some("pub_general"));
    }

    #[test]
    fn resolve_returns_none_for_unknown_hash() {
        let reg = TopicRegistry::new();
        let topic = libp2p::gossipsub::Sha256Topic::new("pub_unknown");
        assert_eq!(reg.resolve(&topic.hash()), None);
    }

    #[test]
    fn resolve_returns_none_after_unsubscribe() {
        let mut reg = TopicRegistry::new();
        reg.subscribe("pub_general");
        reg.unsubscribe("pub_general");
        let topic = libp2p::gossipsub::Sha256Topic::new("pub_general");
        assert_eq!(reg.resolve(&topic.hash()), None);
    }

    #[test]
    fn len_and_is_empty() {
        let mut reg = TopicRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);

        reg.subscribe("pub_a");
        reg.subscribe("pub_b");
        assert_eq!(reg.len(), 2);
        assert!(!reg.is_empty());

        reg.unsubscribe("pub_a");
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn subscriptions_returns_all_active() {
        let mut reg = TopicRegistry::new();
        reg.subscribe("pub_general");
        reg.subscribe("prv_alice_bob");

        let subs = reg.subscriptions();
        assert_eq!(subs.len(), 2);

        let values: Vec<&str> = subs.values().map(|s| s.as_str()).collect();
        assert!(values.contains(&"pub_general"));
        assert!(values.contains(&"prv_alice_bob"));
    }

    #[test]
    fn multiple_topics_independent() {
        let mut reg = TopicRegistry::new();
        reg.subscribe("pub_general");
        reg.subscribe("pub_announce");

        reg.unsubscribe("pub_general");

        let topic_announce = libp2p::gossipsub::Sha256Topic::new("pub_announce");
        let topic_general = libp2p::gossipsub::Sha256Topic::new("pub_general");

        assert_eq!(reg.resolve(&topic_announce.hash()), Some("pub_announce"));
        assert_eq!(reg.resolve(&topic_general.hash()), None);
    }

    #[test]
    fn default_is_empty() {
        let reg = TopicRegistry::default();
        assert!(reg.is_empty());
    }
}
