use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::hash::HashFunction;

pub const STEM_SUBTREE_WIDTH: usize = 256;
pub const EMPTY_VALUE: [u8; 32] = [0u8; 32];

pub trait TreeHasher {
    fn hash(&self, input: &[u8]) -> [u8; 32];

    fn hash_pair(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut payload = Vec::<u8>::with_capacity(64);
        payload.extend_from_slice(left);
        payload.extend_from_slice(right);
        self.hash(&payload)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3Hasher;

impl TreeHasher for Blake3Hasher {
    fn hash(&self, input: &[u8]) -> [u8; 32] {
        *blake3::hash(input).as_bytes()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ModeHasher {
    pub mode: HashFunction,
}

impl TreeHasher for ModeHasher {
    fn hash(&self, input: &[u8]) -> [u8; 32] {
        if self.mode == HashFunction::Gemini && input.starts_with(b"PBT:STEM:v1") {
            let tag_len = b"PBT:STEM:v1".len();
            let values_bytes = STEM_SUBTREE_WIDTH * 32;
            if input.len() >= tag_len + values_bytes {
                let prefix_len = input.len() - tag_len - values_bytes;
                let prefix = &input[tag_len..tag_len + prefix_len];
                let values_slice = &input[tag_len + prefix_len..];
                let mut values = [[0u8; 32]; STEM_SUBTREE_WIDTH];
                for (i, chunk) in values_slice.chunks_exact(32).enumerate() {
                    values[i].copy_from_slice(chunk);
                }
                return crate::hash::hash_stem(prefix, &values, self.mode);
            }
        }
        crate::hash::hash_bytes(input, self.mode)
    }

    fn hash_pair(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        crate::hash::tree_hash(left, right, self.mode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StemNode {
    pub stem_prefix: Vec<u8>,
    pub values: [[u8; 32]; STEM_SUBTREE_WIDTH],
}

impl StemNode {
    pub fn new(stem_prefix: Vec<u8>) -> Self {
        Self {
            stem_prefix,
            values: [EMPTY_VALUE; STEM_SUBTREE_WIDTH],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.values.iter().all(|value| value == &EMPTY_VALUE)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalNode {
    pub left: Node,
    pub right: Node,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Empty,
    Internal(Box<InternalNode>),
    Stem(StemNode),
}

impl Default for Node {
    fn default() -> Self {
        Node::Empty
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProof {
    pub key: Vec<u8>,
    pub value: [u8; 32],
    pub stem_values: Vec<[u8; 32]>,
    pub path_siblings: Vec<[u8; 32]>,
    pub path_bits: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchMerkleProof {
    pub keys: Vec<Vec<u8>>,
    pub values: Vec<[u8; 32]>,
    pub proofs: Vec<MerkleProof>,
    pub deduplicated_siblings: Vec<[u8; 32]>,
    pub key_to_proof_index: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct Tree<H: TreeHasher + Clone> {
    pub root: Node,
    pub hasher: H,
}

impl<H: TreeHasher + Clone> Tree<H> {
    pub fn new(hasher: H) -> Self {
        Self {
            root: Node::Empty,
            hasher,
        }
    }

    pub fn root_hash(&self) -> [u8; 32] {
        node_hash(&self.root, &self.hasher)
    }

    pub fn insert(&mut self, key: &[u8], value: [u8; 32]) -> Result<(), String> {
        let (stem_prefix, subindex) = split_key(key)?;
        let current = std::mem::replace(&mut self.root, Node::Empty);
        self.root = insert_node(current, stem_prefix, subindex, value, 0, &self.hasher);
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Result<[u8; 32], String> {
        let (stem_prefix, subindex) = split_key(key)?;
        Ok(get_node(&self.root, &stem_prefix, subindex, 0))
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<(), String> {
        let (stem_prefix, subindex) = split_key(key)?;
        let current = std::mem::replace(&mut self.root, Node::Empty);
        self.root = delete_node(current, &stem_prefix, subindex, 0, &self.hasher);
        Ok(())
    }

    pub fn get_proof(&self, key: &[u8]) -> Result<MerkleProof, String> {
        let (stem_prefix, subindex) = split_key(key)?;
        let mut siblings: Vec<[u8; 32]> = Vec::new();
        let mut bits: Vec<u8> = Vec::new();

        let mut node = &self.root;
        let mut depth = 0usize;
        while let Node::Internal(internal) = node {
            let bit = path_bit_at(&stem_prefix, depth);
            bits.push(bit as u8);
            if bit == 0 {
                siblings.push(node_hash(&internal.right, &self.hasher));
                node = &internal.left;
            } else {
                siblings.push(node_hash(&internal.left, &self.hasher));
                node = &internal.right;
            }
            depth += 1;
        }

        let (value, stem_values) = match node {
            Node::Stem(stem) if stem.stem_prefix == stem_prefix => {
                (stem.values[subindex], stem.values.to_vec())
            }
            _ => (EMPTY_VALUE, vec![EMPTY_VALUE; STEM_SUBTREE_WIDTH]),
        };

        Ok(MerkleProof {
            key: key.to_vec(),
            value,
            stem_values,
            path_siblings: siblings,
            path_bits: bits,
        })
    }

    pub fn verify_proof(&self, root_hash: [u8; 32], proof: &MerkleProof) -> bool {
        verify_proof_with_hasher(root_hash, proof, &self.hasher)
    }

    pub fn get_multi_proof(&self, keys: &[Vec<u8>]) -> Result<BatchMerkleProof, String> {
        let mut unique = BTreeSet::<Vec<u8>>::new();
        for key in keys {
            unique.insert(key.clone());
        }

        let ordered_keys: Vec<Vec<u8>> = unique.into_iter().collect();
        let mut proofs = Vec::<MerkleProof>::new();
        let mut values = Vec::<[u8; 32]>::new();
        let mut sibling_set = BTreeSet::<[u8; 32]>::new();

        for key in &ordered_keys {
            let proof = self.get_proof(key)?;
            values.push(proof.value);
            for sibling in &proof.path_siblings {
                sibling_set.insert(*sibling);
            }
            proofs.push(proof);
        }

        Ok(BatchMerkleProof {
            key_to_proof_index: (0..ordered_keys.len()).collect(),
            deduplicated_siblings: sibling_set.into_iter().collect(),
            keys: ordered_keys,
            values,
            proofs,
        })
    }

    pub fn verify_multi_proof(&self, root_hash: [u8; 32], batch: &BatchMerkleProof) -> bool {
        if batch.keys.windows(2).any(|w| w[0] >= w[1]) {
            return false;
        }
        let n = batch.keys.len();
        if batch.values.len() != n || batch.proofs.len() != n || batch.key_to_proof_index.len() != n {
            return false;
        }
        if batch.key_to_proof_index != (0..n).collect::<Vec<_>>() {
            return false;
        }
        if batch
            .deduplicated_siblings
            .windows(2)
            .any(|w| w[0] > w[1])
        {
            return false;
        }

        for i in 0..n {
            if batch.proofs[i].key != batch.keys[i] {
                return false;
            }
            if batch.proofs[i].value != batch.values[i] {
                return false;
            }
            if !verify_proof_with_hasher(root_hash, &batch.proofs[i], &self.hasher) {
                return false;
            }
        }
        true
    }
}

pub fn split_key(key: &[u8]) -> Result<(Vec<u8>, usize), String> {
    if key.len() < 2 {
        return Err("key must be at least 2 bytes".to_string());
    }
    let subindex = *key.last().unwrap() as usize;
    Ok((key[..key.len() - 1].to_vec(), subindex))
}

fn insert_node(
    node: Node,
    stem_prefix: Vec<u8>,
    subindex: usize,
    value: [u8; 32],
    depth: usize,
    hasher: &impl TreeHasher,
) -> Node {
    match node {
        Node::Empty => {
            let mut stem = StemNode::new(stem_prefix);
            stem.values[subindex] = value;
            Node::Stem(stem)
        }
        Node::Stem(mut stem) => {
            if stem.stem_prefix == stem_prefix {
                stem.values[subindex] = value;
                Node::Stem(stem)
            } else {
                split_stems(stem, stem_prefix, subindex, value, depth, hasher)
            }
        }
        Node::Internal(internal) => {
            let bit = path_bit_at(&stem_prefix, depth);
            if bit == 0 {
                let new_left = insert_node(internal.left, stem_prefix, subindex, value, depth + 1, hasher);
                make_internal(new_left, internal.right, hasher)
            } else {
                let new_right = insert_node(internal.right, stem_prefix, subindex, value, depth + 1, hasher);
                make_internal(internal.left, new_right, hasher)
            }
        }
    }
}

fn split_stems(
    existing: StemNode,
    new_prefix: Vec<u8>,
    subindex: usize,
    value: [u8; 32],
    depth: usize,
    hasher: &impl TreeHasher,
) -> Node {
    let bit_existing = path_bit_at(&existing.stem_prefix, depth);
    let bit_new = path_bit_at(&new_prefix, depth);

    if bit_existing == bit_new {
        let child = split_stems(existing, new_prefix, subindex, value, depth + 1, hasher);
        if bit_existing == 0 {
            make_internal(child, Node::Empty, hasher)
        } else {
            make_internal(Node::Empty, child, hasher)
        }
    } else {
        let mut new_stem = StemNode::new(new_prefix);
        new_stem.values[subindex] = value;
        if bit_new == 0 {
            make_internal(Node::Stem(new_stem), Node::Stem(existing), hasher)
        } else {
            make_internal(Node::Stem(existing), Node::Stem(new_stem), hasher)
        }
    }
}

fn get_node(node: &Node, stem_prefix: &[u8], subindex: usize, depth: usize) -> [u8; 32] {
    match node {
        Node::Empty => EMPTY_VALUE,
        Node::Stem(stem) => {
            if stem.stem_prefix.as_slice() == stem_prefix {
                stem.values[subindex]
            } else {
                EMPTY_VALUE
            }
        }
        Node::Internal(internal) => {
            let bit = path_bit_at(stem_prefix, depth);
            if bit == 0 {
                get_node(&internal.left, stem_prefix, subindex, depth + 1)
            } else {
                get_node(&internal.right, stem_prefix, subindex, depth + 1)
            }
        }
    }
}

fn delete_node(
    node: Node,
    stem_prefix: &[u8],
    subindex: usize,
    depth: usize,
    hasher: &impl TreeHasher,
) -> Node {
    match node {
        Node::Empty => Node::Empty,
        Node::Stem(mut stem) => {
            if stem.stem_prefix.as_slice() != stem_prefix {
                return Node::Stem(stem);
            }
            stem.values[subindex] = EMPTY_VALUE;
            if stem.is_empty() {
                Node::Empty
            } else {
                Node::Stem(stem)
            }
        }
        Node::Internal(internal) => {
            let bit = path_bit_at(stem_prefix, depth);
            let (next_left, next_right) = if bit == 0 {
                (
                    delete_node(internal.left, stem_prefix, subindex, depth + 1, hasher),
                    internal.right,
                )
            } else {
                (
                    internal.left,
                    delete_node(internal.right, stem_prefix, subindex, depth + 1, hasher),
                )
            };

            match (&next_left, &next_right) {
                (Node::Empty, Node::Empty) => Node::Empty,
                (Node::Empty, Node::Stem(_)) => next_right,
                (Node::Stem(_), Node::Empty) => next_left,
                _ => make_internal(next_left, next_right, hasher),
            }
        }
    }
}

fn make_internal(left: Node, right: Node, hasher: &impl TreeHasher) -> Node {
    let hash = internal_hash(&left, &right, hasher);
    Node::Internal(Box::new(InternalNode { left, right, hash }))
}

fn path_bit_at(data: &[u8], position: usize) -> usize {
    let byte_index = position / 8;
    let bit_index = position % 8;
    if byte_index < data.len() {
        ((data[byte_index] >> (7 - bit_index)) & 1) as usize
    } else if byte_index == data.len() && bit_index == 0 {
        1
    } else {
        0
    }
}

fn hash_stem<H: TreeHasher>(stem_prefix: &[u8], values: &[[u8; 32]], hasher: &H) -> [u8; 32] {
    let mut payload = Vec::<u8>::with_capacity(12 + stem_prefix.len() + values.len() * 32);
    payload.extend_from_slice(b"PBT:STEM:v1");
    payload.extend_from_slice(stem_prefix);
    for value in values {
        payload.extend_from_slice(value);
    }
    hasher.hash(&payload)
}

fn internal_hash(left: &Node, right: &Node, hasher: &impl TreeHasher) -> [u8; 32] {
    let left_hash = node_hash(left, hasher);
    let right_hash = node_hash(right, hasher);
    hasher.hash_pair(&left_hash, &right_hash)
}

fn node_hash<H: TreeHasher>(node: &Node, hasher: &H) -> [u8; 32] {
    match node {
        Node::Empty => hasher.hash(b""),
        Node::Stem(stem) => hash_stem(&stem.stem_prefix, &stem.values, hasher),
        Node::Internal(internal) => internal.hash,
    }
}

fn verify_proof_with_hasher<H: TreeHasher + Clone>(
    root_hash: [u8; 32],
    proof: &MerkleProof,
    hasher: &H,
) -> bool {
    if proof.stem_values.len() != STEM_SUBTREE_WIDTH {
        return false;
    }
    let split = split_key(&proof.key);
    if split.is_err() {
        return false;
    }
    let (stem_prefix, subindex) = split.unwrap();
    if proof.stem_values[subindex] != proof.value {
        return false;
    }
    if proof.path_siblings.len() != proof.path_bits.len() {
        return false;
    }

    let mut current = hash_stem(&stem_prefix, &proof.stem_values, hasher);
    for idx in (0..proof.path_siblings.len()).rev() {
        let sibling = proof.path_siblings[idx];
        let bit = proof.path_bits[idx];
        let mut payload = Vec::<u8>::with_capacity(64);
        if bit == 0 {
            payload.extend_from_slice(&current);
            payload.extend_from_slice(&sibling);
        } else if bit == 1 {
            payload.extend_from_slice(&sibling);
            payload.extend_from_slice(&current);
        } else {
            return false;
        }
        current = hasher.hash(&payload);
    }

    current == root_hash
}
