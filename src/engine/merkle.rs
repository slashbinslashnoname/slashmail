//! Bucket-based Merkle tree for efficient message set reconciliation.
//!
//! Messages are assigned to one of [`NUM_BUCKETS`] buckets based on the first
//! byte of `SHA-256(message_id)`. Each bucket hash is the SHA-256 of the sorted
//! concatenation of its message IDs. The root is `SHA-256(bucket_0 || ... || bucket_N)`.
//!
//! This gives a two-level tree: root → bucket hashes → message IDs, enabling
//! efficient delta detection in at most 3 request-response round trips.

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Number of buckets in the Merkle tree (one per possible first byte of hash).
pub const NUM_BUCKETS: usize = 256;

/// A 32-byte SHA-256 hash.
pub type Hash = [u8; 32];

/// The hash used for an empty set of messages.
pub const EMPTY_HASH: Hash = [0u8; 32];

/// A two-level Merkle tree over a set of message IDs.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Per-bucket hashes. `bucket_hashes[i]` is the hash of all message IDs
    /// whose `SHA-256(id)` starts with byte `i`.
    pub bucket_hashes: [Hash; NUM_BUCKETS],
    /// The Merkle root: SHA-256 of all bucket hashes concatenated.
    pub root: Hash,
    /// Per-bucket sorted message IDs (retained for diff computation).
    buckets: Vec<Vec<Uuid>>,
}

impl MerkleTree {
    /// Build a Merkle tree from a list of message IDs.
    pub fn from_ids(ids: &[Uuid]) -> Self {
        let mut buckets: Vec<Vec<Uuid>> = (0..NUM_BUCKETS).map(|_| Vec::new()).collect();

        for id in ids {
            let bucket_idx = bucket_for(id);
            buckets[bucket_idx].push(*id);
        }

        // Sort each bucket for deterministic hashing.
        for bucket in &mut buckets {
            bucket.sort();
        }

        let mut bucket_hashes = [EMPTY_HASH; NUM_BUCKETS];
        for (i, bucket) in buckets.iter().enumerate() {
            bucket_hashes[i] = hash_bucket(bucket);
        }

        let root = hash_root(&bucket_hashes);

        Self {
            bucket_hashes,
            root,
            buckets,
        }
    }

    /// Return the Merkle root hash.
    pub fn root(&self) -> &Hash {
        &self.root
    }

    /// Return the bucket hashes (256 entries).
    pub fn bucket_hashes(&self) -> &[Hash; NUM_BUCKETS] {
        &self.bucket_hashes
    }

    /// Return the sorted message IDs in a given bucket.
    pub fn bucket_ids(&self, index: usize) -> &[Uuid] {
        if index < NUM_BUCKETS {
            &self.buckets[index]
        } else {
            &[]
        }
    }

    /// Find bucket indices where our hashes differ from `other_hashes`.
    pub fn differing_buckets(&self, other_hashes: &[Hash]) -> Vec<u16> {
        self.bucket_hashes
            .iter()
            .zip(other_hashes.iter())
            .enumerate()
            .filter(|(_, (ours, theirs))| ours != theirs)
            .map(|(i, _)| i as u16)
            .collect()
    }

    /// Given a set of remote message IDs for specific buckets, return the IDs
    /// that we are missing locally.
    pub fn missing_ids(&self, remote_bucket_ids: &[(u16, Vec<Uuid>)]) -> Vec<Uuid> {
        let mut missing = Vec::new();
        for (bucket_idx, remote_ids) in remote_bucket_ids {
            let local_ids = self.bucket_ids(*bucket_idx as usize);
            for id in remote_ids {
                if !local_ids.contains(id) {
                    missing.push(*id);
                }
            }
        }
        missing
    }
}

/// Determine the bucket index for a message ID.
fn bucket_for(id: &Uuid) -> usize {
    let hash = Sha256::digest(id.as_bytes());
    hash[0] as usize
}

/// Hash the sorted message IDs in a bucket.
fn hash_bucket(ids: &[Uuid]) -> Hash {
    if ids.is_empty() {
        return EMPTY_HASH;
    }
    let mut hasher = Sha256::new();
    for id in ids {
        hasher.update(id.as_bytes());
    }
    hasher.finalize().into()
}

/// Compute the Merkle root from 256 bucket hashes.
fn hash_root(bucket_hashes: &[Hash; NUM_BUCKETS]) -> Hash {
    let mut hasher = Sha256::new();
    for h in bucket_hashes {
        hasher.update(h);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_has_deterministic_root() {
        let tree = MerkleTree::from_ids(&[]);
        // All buckets empty → all bucket hashes are EMPTY_HASH.
        for bh in tree.bucket_hashes() {
            assert_eq!(*bh, EMPTY_HASH);
        }
        // Root is SHA-256 of 256 zero hashes concatenated.
        let expected_root = hash_root(&[EMPTY_HASH; NUM_BUCKETS]);
        assert_eq!(*tree.root(), expected_root);
    }

    #[test]
    fn identical_id_sets_produce_same_root() {
        let ids: Vec<Uuid> = (0..50).map(|_| Uuid::new_v4()).collect();
        let tree1 = MerkleTree::from_ids(&ids);

        // Shuffle order — root should be the same.
        let mut ids_shuffled = ids.clone();
        ids_shuffled.reverse();
        let tree2 = MerkleTree::from_ids(&ids_shuffled);

        assert_eq!(tree1.root(), tree2.root());
        assert_eq!(tree1.bucket_hashes(), tree2.bucket_hashes());
    }

    #[test]
    fn different_id_sets_produce_different_roots() {
        let ids_a: Vec<Uuid> = (0..10).map(|_| Uuid::new_v4()).collect();
        let ids_b: Vec<Uuid> = (0..10).map(|_| Uuid::new_v4()).collect();
        let tree_a = MerkleTree::from_ids(&ids_a);
        let tree_b = MerkleTree::from_ids(&ids_b);
        assert_ne!(tree_a.root(), tree_b.root());
    }

    #[test]
    fn differing_buckets_detects_changes() {
        let ids: Vec<Uuid> = (0..50).map(|_| Uuid::new_v4()).collect();
        let tree = MerkleTree::from_ids(&ids);

        // Same tree → no differences.
        assert!(tree.differing_buckets(tree.bucket_hashes()).is_empty());

        // Modify one bucket hash → detected.
        let mut altered = *tree.bucket_hashes();
        altered[42] = [0xFF; 32];
        let diffs = tree.differing_buckets(&altered);
        assert!(diffs.contains(&42));
    }

    #[test]
    fn missing_ids_finds_absent_messages() {
        let shared: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();
        let extra = Uuid::new_v4();

        let local_tree = MerkleTree::from_ids(&shared);

        // Remote has an extra ID in some bucket.
        let extra_bucket = {
            let hash = Sha256::digest(extra.as_bytes());
            hash[0] as u16
        };
        let mut remote_ids = local_tree.bucket_ids(extra_bucket as usize).to_vec();
        remote_ids.push(extra);

        let missing = local_tree.missing_ids(&[(extra_bucket, remote_ids)]);
        assert_eq!(missing, vec![extra]);
    }

    #[test]
    fn bucket_ids_returns_sorted() {
        let ids: Vec<Uuid> = (0..100).map(|_| Uuid::new_v4()).collect();
        let tree = MerkleTree::from_ids(&ids);

        for i in 0..NUM_BUCKETS {
            let bucket = tree.bucket_ids(i);
            for window in bucket.windows(2) {
                assert!(window[0] <= window[1], "bucket {i} not sorted");
            }
        }
    }

    #[test]
    fn single_id_tree() {
        let id = Uuid::new_v4();
        let tree = MerkleTree::from_ids(&[id]);

        // Only one bucket should be non-empty.
        let non_empty: Vec<_> = (0..NUM_BUCKETS)
            .filter(|i| !tree.bucket_ids(*i).is_empty())
            .collect();
        assert_eq!(non_empty.len(), 1);
        assert_eq!(tree.bucket_ids(non_empty[0]), &[id]);
    }

    #[test]
    fn bucket_ids_out_of_range_returns_empty() {
        let tree = MerkleTree::from_ids(&[]);
        assert!(tree.bucket_ids(999).is_empty());
    }

    #[test]
    fn root_is_stable_across_calls() {
        // Fixed UUID ensures root is deterministic across runs.
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let root1 = *MerkleTree::from_ids(&[id]).root();
        let root2 = *MerkleTree::from_ids(&[id]).root();
        assert_eq!(root1, root2);
        // And different from empty tree.
        assert_ne!(root1, *MerkleTree::from_ids(&[]).root());
    }

    #[test]
    fn empty_root_differs_from_all_zero_hash() {
        // The empty root is SHA-256 of 256 zero-hashes, not zero itself.
        let tree = MerkleTree::from_ids(&[]);
        assert_ne!(*tree.root(), EMPTY_HASH);
    }
}
