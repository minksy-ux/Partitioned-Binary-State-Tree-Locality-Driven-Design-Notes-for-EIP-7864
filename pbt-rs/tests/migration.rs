use pbt_rs::{
    migrate_account,
    MptAccount,
    Blake3Hasher,
    Tree,
    get_tree_key_for_basic_data,
    get_tree_key_for_storage_slot,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FixtureStorage {
    slot: usize,
    value_hex: String,
}

#[derive(Debug, Deserialize)]
struct FixtureAccount {
    address_hex: String,
    version: u32,
    balance: u64,
    nonce: u64,
    code_hex: String,
    code_hash_hex: String,
    storage: Vec<FixtureStorage>,
}

#[derive(Debug, Deserialize)]
struct MigrationFixture {
    accounts: Vec<FixtureAccount>,
}

fn parse_hex_32(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).expect("valid hex required");
    assert_eq!(bytes.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn fixture_to_account(input: &FixtureAccount) -> MptAccount {
    let code_bytes = hex::decode(&input.code_hex).expect("code hex must decode");
    let storage = input
        .storage
        .iter()
        .map(|entry| (entry.slot, parse_hex_32(&entry.value_hex)))
        .collect::<Vec<_>>();

    MptAccount {
        address: parse_hex_32(&input.address_hex),
        version: input.version,
        balance: input.balance,
        nonce: input.nonce,
        code: code_bytes,
        code_hash: parse_hex_32(&input.code_hash_hex),
        storage,
    }
}

#[test]
fn migrate_account_populates_basic_data_and_code_hash() {
    let mut tree = Tree::new(Blake3Hasher);
    let account = MptAccount {
        address: [0xAB; 32],
        version: 1,
        balance: 10,
        nonce: 3,
        code: vec![0x60, 0x00, 0x60, 0x01],
        code_hash: [0xCC; 32],
        storage: vec![(0, [0x11; 32]), (1, [0x22; 32])],
    };

    migrate_account(&mut tree, &account).expect("migration should succeed");

    let basic_key = get_tree_key_for_basic_data(account.address);
    let basic = tree.get(&basic_key).expect("get should succeed");
    assert_ne!(basic, [0u8; 32]);

    let mut code_hash_key = basic_key.clone();
    let last = code_hash_key.len() - 1;
    code_hash_key[last] = 1;
    let code_hash = tree.get(&code_hash_key).expect("get should succeed");
    assert_eq!(code_hash, account.code_hash);
}

#[test]
fn migration_fixture_is_deterministic_and_populates_storage() {
    let fixture_text = include_str!("vectors/migration_fixture.json");
    let fixture: MigrationFixture =
        serde_json::from_str(fixture_text).expect("fixture json should parse");

    let mut tree_forward = Tree::new(Blake3Hasher);
    let mut converted = Vec::<MptAccount>::new();
    for item in &fixture.accounts {
        let account = fixture_to_account(item);
        migrate_account(&mut tree_forward, &account).expect("migration should succeed");
        converted.push(account);
    }

    let mut tree_reverse = Tree::new(Blake3Hasher);
    for account in converted.iter().rev() {
        migrate_account(&mut tree_reverse, account).expect("migration should succeed");
    }

    assert_eq!(tree_forward.root_hash(), tree_reverse.root_hash());

    for account in &converted {
        let basic_key = get_tree_key_for_basic_data(account.address);
        let basic = tree_forward.get(&basic_key).expect("get should succeed");
        assert_ne!(basic, [0u8; 32]);

        for (slot, expected) in &account.storage {
            let key = get_tree_key_for_storage_slot(account.address, *slot);
            let got = tree_forward.get(&key).expect("get should succeed");
            assert_eq!(got, *expected);
        }
    }
}
