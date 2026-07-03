use pbt_rs::{
    get_tree_key,
    Blake3Hasher,
    Tree,
    HEADER_SUBTREE,
    get_tree_key_for_storage_slot,
};

fn val(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

#[test]
fn insert_prove_verify_round_trip() {
    let mut tree = Tree::new(Blake3Hasher);
    let key = get_tree_key(HEADER_SUBTREE, &[0xAA; 32], 7);
    let value = val(777);

    tree.insert(&key, value).expect("insert should succeed");
    let root = tree.root_hash();

    let proof = tree.get_proof(&key).expect("proof generation should succeed");
    assert_eq!(proof.value, value);
    assert!(tree.verify_proof(root, &proof));
}

#[test]
fn canonical_locality_same_stem_preserved() {
    let mut tree = Tree::new(Blake3Hasher);
    let address = [0x11u8; 32];

    for slot in 0..4usize {
        let key = get_tree_key_for_storage_slot(address, slot);
        tree.insert(&key, val(slot as u64)).expect("insert should succeed");
    }

    for slot in 0..4usize {
        let key = get_tree_key_for_storage_slot(address, slot);
        assert_eq!(tree.get(&key).expect("get should succeed"), val(slot as u64));
    }
}

#[test]
fn multi_proof_round_trip() {
    let mut tree = Tree::new(Blake3Hasher);
    let k1 = get_tree_key(HEADER_SUBTREE, &[0x01; 32], 1);
    let k2 = get_tree_key(HEADER_SUBTREE, &[0x02; 32], 2);
    let k3 = get_tree_key(HEADER_SUBTREE, &[0x03; 32], 3);

    tree.insert(&k1, val(1)).expect("insert should succeed");
    tree.insert(&k2, val(2)).expect("insert should succeed");
    tree.insert(&k3, val(3)).expect("insert should succeed");

    let root = tree.root_hash();
    let batch = tree
        .get_multi_proof(&vec![k3.clone(), k1.clone(), k2.clone(), k2.clone()])
        .expect("multi proof generation should succeed");

    assert!(tree.verify_multi_proof(root, &batch));
    assert_eq!(batch.keys, vec![k1, k2, k3]);
}
