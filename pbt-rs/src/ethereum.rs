use crate::tree::STEM_SUBTREE_WIDTH;
use crate::HashFunction;
use tiny_keccak::{Hasher, Keccak};

pub const HEADER_SUBTREE: u8 = 0;
pub const CODE_SUBTREE: u8 = 1;
pub const STORAGE_SUBTREE: u8 = 255;

pub const BASIC_DATA_LEAF_KEY: u8 = 0;
pub const CODE_HASH_LEAF_KEY: u8 = 1;
pub const CODE_OFFSET: usize = 4;
pub const HEADER_STORAGE_OFFSET: usize = 20;
pub const CODE_CHUNKS_IN_HEADER: usize = 16;
pub const STORAGE_CHUNKS_IN_HEADER: usize = 4;

fn blake3_32(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

fn int_to_bytes32(value: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = value.to_be_bytes();
    let offset = 32 - bytes.len();
    out[offset..].copy_from_slice(&bytes);
    out
}

pub fn get_tree_key(storage_type: u8, tree_position: &[u8], subindex: u8) -> Vec<u8> {
    let mut key = Vec::<u8>::with_capacity(1 + tree_position.len() + 1);
    key.push(storage_type);
    key.extend_from_slice(tree_position);
    key.push(subindex);
    key
}

pub fn get_tree_key_for_basic_data(address: [u8; 32]) -> Vec<u8> {
    let mut preimage = Vec::<u8>::with_capacity(11 + 32);
    preimage.extend_from_slice(b"PBT:HEADER:v1");
    preimage.extend_from_slice(&address);
    let position = blake3_32(&preimage);
    get_tree_key(HEADER_SUBTREE, &position, BASIC_DATA_LEAF_KEY)
}

pub fn get_header_stem_key(address: &[u8; 32]) -> Vec<u8> {
    let mut key = vec![HEADER_SUBTREE];
    key.extend_from_slice(&keccak256(address));
    key
}

fn mode_tag(mode: HashFunction) -> &'static [u8] {
    match mode {
        HashFunction::Blake3 => b"blake3",
        HashFunction::Poseidon2 => b"poseidon2",
        HashFunction::Gemini => b"gemini",
    }
}

pub fn compute_execution_root_commitment(root: [u8; 32], mode: HashFunction) -> [u8; 32] {
    let mut preimage = Vec::<u8>::with_capacity(22 + 8 + 32);
    preimage.extend_from_slice(b"PBT:EXEC:COMMITMENT:v1");
    preimage.extend_from_slice(mode_tag(mode));
    preimage.extend_from_slice(&root);
    keccak256(&preimage)
}

pub fn compute_vector_fold_commitment(
    final_root: [u8; 32],
    mode: HashFunction,
    stem_count: usize,
) -> [u8; 32] {
    let mut preimage = Vec::<u8>::with_capacity(28 + 8 + 32 + 32);
    preimage.extend_from_slice(b"PBT:VECTORFOLD:COMMITMENT:v1");
    preimage.extend_from_slice(mode_tag(mode));
    preimage.extend_from_slice(&final_root);
    preimage.extend_from_slice(&int_to_bytes32(stem_count));
    keccak256(&preimage)
}

pub fn get_tree_key_for_code_chunk(address: [u8; 32], chunk_id: usize) -> Vec<u8> {
    let mut header_preimage = Vec::<u8>::with_capacity(11 + 32);
    header_preimage.extend_from_slice(b"PBT:HEADER:v1");
    header_preimage.extend_from_slice(&address);
    let header_position = blake3_32(&header_preimage);

    if chunk_id < CODE_CHUNKS_IN_HEADER {
        return get_tree_key(HEADER_SUBTREE, &header_position, (CODE_OFFSET + chunk_id) as u8);
    }

    let overflow = chunk_id - CODE_CHUNKS_IN_HEADER;
    let high = overflow / STEM_SUBTREE_WIDTH;
    let low = overflow % STEM_SUBTREE_WIDTH;

    let mut preimage = Vec::<u8>::with_capacity(9 + 32 + 32);
    preimage.extend_from_slice(b"PBT:CODE:v1");
    preimage.extend_from_slice(&address);
    preimage.extend_from_slice(&int_to_bytes32(high));
    let code_position = blake3_32(&preimage);
    get_tree_key(CODE_SUBTREE, &code_position, low as u8)
}

pub fn get_tree_key_for_storage_slot(address: [u8; 32], storage_key: usize) -> Vec<u8> {
    let mut header_preimage = Vec::<u8>::with_capacity(11 + 32);
    header_preimage.extend_from_slice(b"PBT:HEADER:v1");
    header_preimage.extend_from_slice(&address);
    let header_position = blake3_32(&header_preimage);

    if storage_key < STORAGE_CHUNKS_IN_HEADER {
        return get_tree_key(
            HEADER_SUBTREE,
            &header_position,
            (HEADER_STORAGE_OFFSET + storage_key) as u8,
        );
    }

    let overflow = storage_key - STORAGE_CHUNKS_IN_HEADER;
    let high = overflow / STEM_SUBTREE_WIDTH;
    let low = overflow % STEM_SUBTREE_WIDTH;

    let mut part_a = Vec::<u8>::with_capacity(13 + 32);
    part_a.extend_from_slice(b"PBT:STORAGE:v1");
    part_a.extend_from_slice(&address);

    let mut part_b = Vec::<u8>::with_capacity(13 + 32 + 32);
    part_b.extend_from_slice(b"PBT:STORAGE:v1");
    part_b.extend_from_slice(&address);
    part_b.extend_from_slice(&int_to_bytes32(high));

    let mut storage_position = Vec::<u8>::with_capacity(64);
    storage_position.extend_from_slice(&blake3_32(&part_a));
    storage_position.extend_from_slice(&blake3_32(&part_b));

    get_tree_key(STORAGE_SUBTREE, &storage_position, low as u8)
}
