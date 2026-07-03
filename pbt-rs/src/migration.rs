use crate::ethereum::{
    get_tree_key_for_basic_data, get_tree_key_for_code_chunk, get_tree_key_for_storage_slot,
};
use crate::tree::{Tree, TreeHasher};

#[derive(Debug, Clone)]
pub struct MptAccount {
    pub address: [u8; 32],
    pub version: u32,
    pub balance: u64,
    pub nonce: u64,
    pub code: Vec<u8>,
    pub code_hash: [u8; 32],
    pub storage: Vec<(usize, [u8; 32])>,
}

fn encode_basic_data(version: u32, balance: u64, nonce: u64, code_size: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&version.to_be_bytes());
    out[4..12].copy_from_slice(&balance.to_be_bytes());
    out[12..20].copy_from_slice(&nonce.to_be_bytes());

    let code_size_u128 = code_size as u128;
    let bytes = code_size_u128.to_be_bytes();
    out[20..32].copy_from_slice(&bytes[4..16]);
    out
}

fn chunk_code(code: &[u8]) -> Vec<[u8; 32]> {
    if code.is_empty() {
        return Vec::new();
    }
    let mut chunks = Vec::<[u8; 32]>::new();
    let mut i = 0usize;
    while i < code.len() {
        let end = std::cmp::min(i + 31, code.len());
        let mut chunk = [0u8; 32];
        // pushdata offset placeholder at byte 0
        chunk[1..(1 + end - i)].copy_from_slice(&code[i..end]);
        chunks.push(chunk);
        i += 31;
    }
    chunks
}

pub fn migrate_account<H: TreeHasher + Clone>(
    tree: &mut Tree<H>,
    account: &MptAccount,
) -> Result<(), String> {
    let basic_key = get_tree_key_for_basic_data(account.address);
    let basic = encode_basic_data(
        account.version,
        account.balance,
        account.nonce,
        account.code.len(),
    );
    tree.insert(&basic_key, basic)?;

    // Code hash leaf is subindex 1 in header stem (same as Python embedding).
    let mut code_hash_key = get_tree_key_for_basic_data(account.address);
    let last = code_hash_key.len() - 1;
    code_hash_key[last] = 1;
    tree.insert(&code_hash_key, account.code_hash)?;

    for (chunk_id, chunk) in chunk_code(&account.code).iter().enumerate() {
        let key = get_tree_key_for_code_chunk(account.address, chunk_id);
        tree.insert(&key, *chunk)?;
    }

    for (slot, value) in &account.storage {
        let key = get_tree_key_for_storage_slot(account.address, *slot);
        tree.insert(&key, *value)?;
    }

    Ok(())
}
