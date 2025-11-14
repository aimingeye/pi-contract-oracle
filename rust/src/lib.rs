//! High-performance Merkle tree implementation for tamper-evident data commitments.
//!
//! This library provides cryptographic primitives for the Pi Oracle system,
//! enabling efficient construction and verification of Merkle proofs for market data.
//!
//! # Examples
//!
//! ```
//! use pi_oracle_core::{MerkleTree, verify_proof};
//!
//! let data = vec![b"tick1".as_slice(), b"tick2".as_slice()];
//! let tree = MerkleTree::new(data);
//! let root = tree.root();
//!
//! let proof = tree.generate_proof(0).unwrap();
//! assert!(verify_proof(&proof));
//! ```

use sha2::{Digest, Sha256};
use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer, Verifier} };
use rand::rngs::OsRng;

/// Computes SHA-256 hash of input data.
///
/// # Examples
///
/// ```
/// use pi_oracle_core::hash_data;
/// let hash = hash_data(b"market data");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Concatenates and hashes two byte slices.
fn hash_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
    let combined = [left, right].concat();
    hash_data(&combined)
}

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_bytes = signing_key.to_bytes().to_vec();
    let public_bytes = verifying_key.to_sec1_bytes().to_vec();
    
    (private_bytes, public_bytes)
}

pub fn sign_message(message: &[u8], private_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let signing_key = SigningKey::from_bytes(private_bytes.into())
        .map_err(|e| format!("Invalid private key: {}", e))?;
    
    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

pub fn verify_signature(
    message: &[u8], 
    signature_bytes: &[u8], 
    public_bytes: &[u8]
) -> bool {
    let verifying_key = match VerifyingKey::from_sec1_bytes(public_bytes) {
        Ok(key) => key,
        Err(_) => return false,
    };
    
    let signature = match Signature::from_bytes(signature_bytes.into()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    verifying_key.verify(message, &signature).is_ok()
}

/// Binary Merkle tree for creating cryptographic commitments.
///
/// Constructs a balanced binary tree where leaves are hashes of input data
/// and internal nodes are hashes of their children. Enables O(log n) proof
/// generation and verification.
pub struct MerkleTree {
    root: Vec<u8>,
    leaves: Vec<Vec<u8>>,
    layers: Vec<Vec<Vec<u8>>>,
}

/// Cryptographic proof that data exists in a Merkle tree.
///
/// Contains the minimal set of sibling hashes needed to recompute
/// the root hash from a leaf, proving inclusion without revealing
/// other tree data.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: Vec<u8>,
    pub siblings: Vec<Vec<u8>>,
    pub root: Vec<u8>,
}

impl MerkleTree {
    /// Constructs a Merkle tree from data items.
    ///
    /// Hashes each data item to create leaves, then recursively builds
    /// parent layers until reaching a single root hash. For odd-length
    /// layers, the last element is duplicated.
    ///
    /// # Examples
    ///
    /// ```
    /// use pi_oracle_core::MerkleTree;
    /// let data = vec![b"data1".as_slice(), b"data2".as_slice()];
    /// let tree = MerkleTree::new(data);
    /// assert_eq!(tree.root().len(), 32);
    /// ```
    pub fn new(data_items: Vec<&[u8]>) -> Self {
        let mut leaves: Vec<Vec<u8>> = data_items
            .iter()
            .map(|item| hash_data(item))
            .collect();
        
        if leaves.len() % 2 == 1 {
            leaves.push(leaves.last().unwrap().clone());
        }

        let mut layers: Vec<Vec<Vec<u8>>> = vec![leaves.clone()];
        let mut current_layer = leaves.clone();
        
        while current_layer.len() > 1 {
            let mut next_layer: Vec<Vec<u8>> = Vec::new();
            
            for i in (0..current_layer.len()).step_by(2) {
                let left = &current_layer[i];
                let right = if i + 1 < current_layer.len() {
                    &current_layer[i + 1]
                } else {
                    left
                };
                
                next_layer.push(hash_pair(left, right));
            }
            
            layers.push(next_layer.clone());
            current_layer = next_layer;
        }
        
        let root = current_layer[0].clone();

        Self {
            leaves,
            layers,
            root,
        }
    }

    /// Returns the Merkle root hash.
    pub fn root(&self) -> &[u8] {
        &self.root
    }

    /// Generates a cryptographic proof for the leaf at the given index.
    ///
    /// Returns `None` if the index is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use pi_oracle_core::MerkleTree;
    /// let data = vec![b"a".as_slice(), b"b".as_slice()];
    /// let tree = MerkleTree::new(data);
    /// let proof = tree.generate_proof(0).unwrap();
    /// assert_eq!(proof.leaf_index, 0);
    /// ```
    pub fn generate_proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut current_index = index;

        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < layer.len() {
                siblings.push(layer[sibling_index].clone());
            }

            current_index /= 2;
        }

        Some(MerkleProof {
            leaf_index: index,
            leaf_hash: self.leaves[index].clone(),
            siblings,
            root: self.root.clone(),
        })
    }
}

/// Verifies a Merkle proof by recomputing the root hash.
///
/// Returns `true` if the proof is valid and the recomputed root
/// matches the root claimed in the proof.
///
/// # Examples
///
/// ```
/// use pi_oracle_core::{MerkleTree, verify_proof};
/// let data = vec![b"data".as_slice()];
/// let tree = MerkleTree::new(data);
/// let proof = tree.generate_proof(0).unwrap();
/// assert!(verify_proof(&proof));
/// ```
pub fn verify_proof(proof: &MerkleProof) -> bool {
    let mut current_hash = proof.leaf_hash.clone();
    let mut current_index = proof.leaf_index;

    for sibling in &proof.siblings {
        current_hash = if current_index % 2 == 0 {
            hash_pair(&current_hash, sibling)
        } else {
            hash_pair(sibling, &current_hash)
        };
        current_index /= 2;
    }

    current_hash == proof.root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let data = b"test data";
        let hash1 = hash_data(data);
        let hash2 = hash_data(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_length() {
        let hash = hash_data(b"any data");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_different_data_different_hash() {
        let hash1 = hash_data(b"data1");
        let hash2 = hash_data(b"data2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_merkle_single_item() {
        let data = vec![b"single".as_slice()];
        let tree = MerkleTree::new(data);
        assert_eq!(tree.root().len(), 32);
    }

    #[test]
    fn test_merkle_two_items() {
        let data = vec![b"item1".as_slice(), b"item2".as_slice()];
        let tree = MerkleTree::new(data);
        assert_eq!(tree.root().len(), 32);
    }

    #[test]
    fn test_merkle_odd_items() {
        let data = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
        let tree = MerkleTree::new(data);
        assert_eq!(tree.root().len(), 32);
    }

    #[test]
    fn test_merkle_many_items() {
        let items: Vec<String> = (0..8).map(|i| format!("item{}", i)).collect();
        let data: Vec<&[u8]> = items.iter().map(|s| s.as_bytes()).collect();
        let tree = MerkleTree::new(data);
        assert_eq!(tree.root().len(), 32);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let data = vec![
            b"tick1".as_slice(),
            b"tick2".as_slice(),
            b"tick3".as_slice(),
            b"tick4".as_slice(),
        ];
        let tree = MerkleTree::new(data);

        for i in 0..4 {
            let proof = tree.generate_proof(i).unwrap();
            assert_eq!(proof.leaf_index, i);
            assert!(verify_proof(&proof));
        }
    }

    #[test]
    fn test_proof_invalid_index() {
        let data = vec![b"a".as_slice(), b"b".as_slice()];
        let tree = MerkleTree::new(data);
        assert!(tree.generate_proof(100).is_none());
    }

    #[test]
    fn test_proof_tamper_detection() {
        let data = vec![b"a".as_slice(), b"b".as_slice()];
        let tree = MerkleTree::new(data);
        let mut proof = tree.generate_proof(0).unwrap();
        proof.leaf_hash[0] ^= 0xFF;
        assert!(!verify_proof(&proof));
    }

    #[test]
    fn test_market_tick_simulation() {
        let ticks = vec![
            b"{\"price\":100.5,\"vol\":1000}".as_slice(),
            b"{\"price\":100.6,\"vol\":1500}".as_slice(),
            b"{\"price\":100.4,\"vol\":800}".as_slice(),
            b"{\"price\":100.7,\"vol\":2000}".as_slice(),
        ];
        let tree = MerkleTree::new(ticks);
        for i in 0..4 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(verify_proof(&proof));
        }
    }

    #[test]
    fn test_keypair_generation() {
        let (private_key, public_key) = generate_keypair();
        assert_eq!(private_key.len(), 32);
        assert!(public_key.len() == 33 || public_key.len() == 65);
    }

    #[test]
    fn test_sign_and_verify() {
        let (private_key, public_key) = generate_keypair();
        let message = b"test message";
        
        let signature = sign_message(message, &private_key).unwrap();
        assert!(verify_signature(message, &signature, &public_key));
    }

    #[test]
    fn test_sign_merkle_root() {
        // Build Merkle tree
        let data = vec![b"tick1".as_slice(), b"tick2".as_slice()];
        let tree = MerkleTree::new(data);
        let root = tree.root();
        
        // Generate keys and sign root
        let (private_key, public_key) = generate_keypair();
        let signature = sign_message(root, &private_key).unwrap();
        
        // Verify signature
        assert!(verify_signature(root, &signature, &public_key));
    }

    #[test]
    fn test_invalid_signature() {
        let (private_key, public_key) = generate_keypair();
        let message = b"test message";
        
        let signature = sign_message(message, &private_key).unwrap();
        
        // Wrong message should fail
        let wrong_message = b"different message";
        assert!(!verify_signature(wrong_message, &signature, &public_key));
    }
}
