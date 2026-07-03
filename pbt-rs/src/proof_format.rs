use crate::tree::{BatchMerkleProof, Tree, TreeHasher};
use crate::{hash_stem, tree_hash, HashFunction, STEM_SUBTREE_WIDTH};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Read, Write};

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ProofMode {
    Blake3,
    Poseidon2,
    GeminiHash,
}

impl ProofMode {
    fn as_hash_function(self) -> HashFunction {
        match self {
            ProofMode::Blake3 => HashFunction::Blake3,
            ProofMode::Poseidon2 => HashFunction::Poseidon2,
            ProofMode::GeminiHash => HashFunction::Gemini,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FoldStep {
    pub fold_factor: u8,
    pub commitment: [u8; 32],
    pub proof_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorFoldProof {
    pub key: Vec<u8>,
    pub value: [u8; 32],
    pub stem_values: [[u8; 32]; STEM_SUBTREE_WIDTH],
    pub path_folds: Vec<FoldStep>,
    pub final_root: [u8; 32],
    pub mode: ProofMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VectorFoldProofSerde {
    key: Vec<u8>,
    value: [u8; 32],
    stem_values: Vec<[u8; 32]>,
    path_folds: Vec<FoldStep>,
    final_root: [u8; 32],
    mode: ProofMode,
}

impl Serialize for VectorFoldProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let repr = VectorFoldProofSerde {
            key: self.key.clone(),
            value: self.value,
            stem_values: self.stem_values.to_vec(),
            path_folds: self.path_folds.clone(),
            final_root: self.final_root,
            mode: self.mode,
        };
        repr.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VectorFoldProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = VectorFoldProofSerde::deserialize(deserializer)?;
        let stem_values = vec_to_fixed_256(&repr.stem_values)
            .ok_or_else(|| serde::de::Error::custom("invalid stem width in vector fold proof"))?;

        Ok(Self {
            key: repr.key,
            value: repr.value,
            stem_values,
            path_folds: repr.path_folds,
            final_root: repr.final_root,
            mode: repr.mode,
        })
    }
}

fn split_key(key: &[u8]) -> Result<(Vec<u8>, usize), String> {
    if key.len() < 2 {
        return Err("key must be at least 2 bytes".to_string());
    }
    let subindex = *key.last().unwrap() as usize;
    Ok((key[..key.len() - 1].to_vec(), subindex))
}

fn vec_to_fixed_256(values: &[[u8; 32]]) -> Option<[[u8; 32]; 256]> {
    if values.len() != STEM_SUBTREE_WIDTH {
        return None;
    }
    let mut out = [[0u8; 32]; 256];
    out.copy_from_slice(values);
    Some(out)
}

fn compress_bytes(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = GzEncoder::new(Vec::<u8>::new(), Compression::best());
    encoder
        .write_all(raw)
        .map_err(|err| format!("gzip encode write error: {err}"))?;
    encoder
        .finish()
        .map_err(|err| format!("gzip encode finish error: {err}"))
}

fn decompress_bytes(encoded: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = GzDecoder::new(encoded);
    let mut out = Vec::<u8>::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|err| format!("gzip decode error: {err}"))?;
    Ok(out)
}

pub fn encode_batch_proof_json(batch: &BatchMerkleProof) -> Result<String, String> {
    serde_json::to_string(batch).map_err(|err| format!("json encode error: {err}"))
}

pub fn decode_batch_proof_json(data: &str) -> Result<BatchMerkleProof, String> {
    serde_json::from_str(data).map_err(|err| format!("json decode error: {err}"))
}

pub fn encode_batch_proof_bincode(batch: &BatchMerkleProof) -> Result<Vec<u8>, String> {
    bincode::serialize(batch).map_err(|err| format!("bincode encode error: {err}"))
}

pub fn decode_batch_proof_bincode(data: &[u8]) -> Result<BatchMerkleProof, String> {
    bincode::deserialize(data).map_err(|err| format!("bincode decode error: {err}"))
}

pub fn encode_batch_proof_compressed(batch: &BatchMerkleProof) -> Result<Vec<u8>, String> {
    let raw = encode_batch_proof_bincode(batch)?;
    compress_bytes(&raw)
}

pub fn decode_batch_proof_compressed(data: &[u8]) -> Result<BatchMerkleProof, String> {
    let raw = decompress_bytes(data)?;
    decode_batch_proof_bincode(&raw)
}

pub fn verify_batch_proof_wasm<H: TreeHasher + Clone>(
    tree: &Tree<H>,
    root_hash: [u8; 32],
    batch: &BatchMerkleProof,
) -> bool {
    // WASM-target compatible verification entry point.
    tree.verify_multi_proof(root_hash, batch)
}

pub fn build_vector_fold_proof<H: TreeHasher + Clone>(
    tree: &Tree<H>,
    key: &[u8],
    mode: ProofMode,
) -> Result<VectorFoldProof, String> {
    if mode != ProofMode::GeminiHash && mode != ProofMode::Poseidon2 {
        return Err("VectorFold proof mode requires GeminiHash or Poseidon2".to_string());
    }

    let proof = tree.get_proof(key)?;
    let hash_mode = mode.as_hash_function();
    let mut path_folds = Vec::<FoldStep>::new();
    let mut current = hash_stem(
        &split_key(&proof.key)?.0,
        &vec_to_fixed_256(&proof.stem_values)
            .ok_or_else(|| "invalid stem width in proof".to_string())?,
        hash_mode,
    );

    for idx in (0..proof.path_siblings.len()).rev() {
        let sibling = proof.path_siblings[idx];
        let bit = proof.path_bits[idx];
        if bit != 0 && bit != 1 {
            return Err("invalid path bit in proof".to_string());
        }

        let commitment = if bit == 0 {
            tree_hash(&current, &sibling, hash_mode)
        } else {
            tree_hash(&sibling, &current, hash_mode)
        };

        let mut proof_data = Vec::<u8>::with_capacity(33);
        proof_data.push(bit);
        proof_data.extend_from_slice(&sibling);
        path_folds.push(FoldStep {
            fold_factor: 2,
            commitment,
            proof_data,
        });
        current = commitment;
    }

    if current != tree.root_hash() {
        return Err("vector fold mode does not match tree hashing mode".to_string());
    }

    Ok(VectorFoldProof {
        key: proof.key,
        value: proof.value,
        stem_values: vec_to_fixed_256(&proof.stem_values)
            .ok_or_else(|| "invalid stem width in proof".to_string())?,
        path_folds,
        final_root: current,
        mode,
    })
}

pub fn verify_vector_fold_proof(proof: &VectorFoldProof) -> bool {
    if proof.mode != ProofMode::GeminiHash && proof.mode != ProofMode::Poseidon2 {
        return false;
    }

    let hash_mode = proof.mode.as_hash_function();

    let split = split_key(&proof.key);
    if split.is_err() {
        return false;
    }
    let (stem_prefix, subindex) = split.unwrap();
    if proof.stem_values[subindex] != proof.value {
        return false;
    }

    let mut current = hash_stem(&stem_prefix, &proof.stem_values, hash_mode);
    for step in &proof.path_folds {
        if step.fold_factor != 2 {
            return false;
        }
        if step.proof_data.len() != 33 {
            return false;
        }

        let bit = step.proof_data[0];
        if bit != 0 && bit != 1 {
            return false;
        }

        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&step.proof_data[1..33]);

        let expected = if bit == 0 {
            tree_hash(&current, &sibling, hash_mode)
        } else {
            tree_hash(&sibling, &current, hash_mode)
        };
        if expected != step.commitment {
            return false;
        }
        current = expected;
    }

    current == proof.final_root
}

pub fn encode_vector_fold_proof_json(proof: &VectorFoldProof) -> Result<String, String> {
    serde_json::to_string(proof).map_err(|err| format!("json encode error: {err}"))
}

pub fn decode_vector_fold_proof_json(data: &str) -> Result<VectorFoldProof, String> {
    serde_json::from_str(data).map_err(|err| format!("json decode error: {err}"))
}

pub fn encode_vector_fold_proof_bincode(proof: &VectorFoldProof) -> Result<Vec<u8>, String> {
    bincode::serialize(proof).map_err(|err| format!("bincode encode error: {err}"))
}

pub fn decode_vector_fold_proof_bincode(data: &[u8]) -> Result<VectorFoldProof, String> {
    bincode::deserialize(data).map_err(|err| format!("bincode decode error: {err}"))
}

pub fn encode_vector_fold_proof_compressed(proof: &VectorFoldProof) -> Result<Vec<u8>, String> {
    let raw = encode_vector_fold_proof_bincode(proof)?;
    compress_bytes(&raw)
}

pub fn decode_vector_fold_proof_compressed(data: &[u8]) -> Result<VectorFoldProof, String> {
    let raw = decompress_bytes(data)?;
    decode_vector_fold_proof_bincode(&raw)
}
