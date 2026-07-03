use crate::tree::{BatchMerkleProof, Tree, TreeHasher};
use crate::{hash_stem, tree_hash, HashFunction, STEM_SUBTREE_WIDTH};

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
    pub left: [u8; 32],
    pub right: [u8; 32],
    pub folded: [u8; 32],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct StemProof {
    pub key: Vec<u8>,
    pub value: [u8; 32],
    pub stem_values: Vec<[u8; 32]>,
    pub path_start: usize,
    pub path_len: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct VectorFoldProof {
    pub stem_proofs: Vec<StemProof>,
    pub path_folds: Vec<FoldStep>,
    pub final_root: [u8; 32],
    pub mode: ProofMode,
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
    keys: &[Vec<u8>],
    mode: ProofMode,
) -> Result<VectorFoldProof, String> {
    let batch = tree.get_multi_proof(keys)?;
    let hash_mode = mode.as_hash_function();

    let mut stem_proofs = Vec::<StemProof>::with_capacity(batch.proofs.len());
    let mut path_folds = Vec::<FoldStep>::new();
    let mut mode_root: Option<[u8; 32]> = None;

    for proof in &batch.proofs {
        let path_start = path_folds.len();
        let mut current = hash_stem(
            &split_key(&proof.key)?.0,
            &vec_to_fixed_256(&proof.stem_values)
                .ok_or_else(|| "invalid stem width in proof".to_string())?,
            hash_mode,
        );

        for idx in (0..proof.path_siblings.len()).rev() {
            let sibling = proof.path_siblings[idx];
            let bit = proof.path_bits[idx];
            let (left, right) = if bit == 0 {
                (current, sibling)
            } else if bit == 1 {
                (sibling, current)
            } else {
                return Err("invalid path bit in batch proof".to_string());
            };
            let folded = tree_hash(&left, &right, hash_mode);
            path_folds.push(FoldStep {
                left,
                right,
                folded,
            });
            current = folded;
        }

        if let Some(existing) = mode_root {
            if existing != current {
                return Err("inconsistent folded roots across stems".to_string());
            }
        } else {
            mode_root = Some(current);
        }

        stem_proofs.push(StemProof {
            key: proof.key.clone(),
            value: proof.value,
            stem_values: proof.stem_values.clone(),
            path_start,
            path_len: path_folds.len() - path_start,
        });
    }

    Ok(VectorFoldProof {
        stem_proofs,
        path_folds,
        final_root: mode_root.unwrap_or([0u8; 32]),
        mode,
    })
}

pub fn verify_vector_fold_proof(proof: &VectorFoldProof) -> bool {
    let hash_mode = proof.mode.as_hash_function();

    for stem in &proof.stem_proofs {
        let split = split_key(&stem.key);
        if split.is_err() {
            return false;
        }
        let (stem_prefix, subindex) = split.unwrap();
        if stem.stem_values.len() != STEM_SUBTREE_WIDTH {
            return false;
        }
        if stem.stem_values[subindex] != stem.value {
            return false;
        }
        if stem.path_start + stem.path_len > proof.path_folds.len() {
            return false;
        }

        let fixed = vec_to_fixed_256(&stem.stem_values);
        if fixed.is_none() {
            return false;
        }
        let mut current = hash_stem(&stem_prefix, &fixed.unwrap(), hash_mode);

        for step in &proof.path_folds[stem.path_start..stem.path_start + stem.path_len] {
            if current != step.left && current != step.right {
                return false;
            }
            if tree_hash(&step.left, &step.right, hash_mode) != step.folded {
                return false;
            }
            current = step.folded;
        }

        if current != proof.final_root {
            return false;
        }
    }

    true
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
