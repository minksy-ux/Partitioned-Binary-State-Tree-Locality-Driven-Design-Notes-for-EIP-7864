use pbt_rs::{
    Blake3Hasher,
    build_vector_fold_proof,
    decode_vector_fold_proof_bincode,
    decode_vector_fold_proof_json,
    encode_vector_fold_proof_bincode,
    encode_vector_fold_proof_json,
    get_tree_key,
    verify_vector_fold_proof,
    HashFunction,
    ModeHasher,
    ProofMode,
    Tree,
    HEADER_SUBTREE,
};

fn key(stem_byte: u8, subindex: u8) -> Vec<u8> {
    let stem = vec![stem_byte; 32];
    get_tree_key(HEADER_SUBTREE, &stem, subindex)
}

#[test]
fn vector_fold_proof_build_verify_and_roundtrip() {
    let mut tree = Tree::new(ModeHasher {
        mode: HashFunction::Gemini,
    });

    let k1 = key(0x11, 0x01);
    let k2 = key(0x11, 0x7F);
    let k3 = key(0xA5, 0x10);

    tree.insert(&k1, [0x10; 32]).expect("insert k1 should succeed");
    tree.insert(&k2, [0x20; 32]).expect("insert k2 should succeed");
    tree.insert(&k3, [0x30; 32]).expect("insert k3 should succeed");

    let proof = build_vector_fold_proof(&tree, &k1, ProofMode::GeminiHash)
        .expect("vector fold proof should build");

    assert!(verify_vector_fold_proof(&proof));

    let json = encode_vector_fold_proof_json(&proof).expect("json encode should succeed");
    let decoded_json = decode_vector_fold_proof_json(&json).expect("json decode should succeed");
    assert!(verify_vector_fold_proof(&decoded_json));

    let bin = encode_vector_fold_proof_bincode(&proof).expect("bincode encode should succeed");
    let decoded_bin = decode_vector_fold_proof_bincode(&bin).expect("bincode decode should succeed");
    assert!(verify_vector_fold_proof(&decoded_bin));
}

#[test]
fn vector_fold_proof_tamper_is_detected() {
    let mut tree = Tree::new(ModeHasher {
        mode: HashFunction::Gemini,
    });

    let k1 = key(0x42, 0x01);
    let k2 = key(0x99, 0xEE);

    tree.insert(&k1, [0xAB; 32]).expect("insert k1 should succeed");
    tree.insert(&k2, [0xCD; 32]).expect("insert k2 should succeed");

    let mut proof = build_vector_fold_proof(&tree, &k1, ProofMode::GeminiHash)
        .expect("vector fold proof should build");
    assert!(verify_vector_fold_proof(&proof));

    if let Some(step) = proof.path_folds.get_mut(0) {
        step.commitment[0] ^= 1;
    }

    assert!(!verify_vector_fold_proof(&proof));
}

#[test]
fn vector_fold_mode_mismatch_is_rejected() {
    let mut tree = Tree::new(Blake3Hasher);
    let key = key(0x77, 0x08);
    tree.insert(&key, [0x44; 32]).expect("insert should succeed");

    let result = build_vector_fold_proof(&tree, &key, ProofMode::GeminiHash);
    assert!(result.is_err());
}
