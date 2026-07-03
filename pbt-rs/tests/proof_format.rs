use pbt_rs::{
    decode_batch_proof_bincode,
    decode_batch_proof_compressed,
    decode_batch_proof_json,
    decode_vector_fold_proof_compressed,
    encode_batch_proof_compressed,
    encode_batch_proof_bincode,
    encode_batch_proof_json,
    encode_vector_fold_proof_compressed,
    build_vector_fold_proof,
    verify_batch_proof_wasm,
    verify_vector_fold_proof,
    get_tree_key,
    Blake3Hasher,
    HashFunction,
    ModeHasher,
    ProofMode,
    Tree,
    HEADER_SUBTREE,
};

fn val(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

#[test]
fn batch_proof_json_and_bincode_round_trip() {
    let mut tree = Tree::new(Blake3Hasher);
    let k1 = get_tree_key(HEADER_SUBTREE, &[0x01; 32], 1);
    let k2 = get_tree_key(HEADER_SUBTREE, &[0x02; 32], 2);

    tree.insert(&k1, val(11)).expect("insert should succeed");
    tree.insert(&k2, val(22)).expect("insert should succeed");

    let root = tree.root_hash();
    let batch = tree
        .get_multi_proof(&vec![k1.clone(), k2.clone()])
        .expect("multi proof generation should succeed");

    let json = encode_batch_proof_json(&batch).expect("json encode should succeed");
    let decoded_json = decode_batch_proof_json(&json).expect("json decode should succeed");
    assert!(verify_batch_proof_wasm(&tree, root, &decoded_json));

    let bin = encode_batch_proof_bincode(&batch).expect("bincode encode should succeed");
    let decoded_bin = decode_batch_proof_bincode(&bin).expect("bincode decode should succeed");
    assert!(verify_batch_proof_wasm(&tree, root, &decoded_bin));

    let compressed =
        encode_batch_proof_compressed(&batch).expect("compressed encode should succeed");
    let decoded_compressed =
        decode_batch_proof_compressed(&compressed).expect("compressed decode should succeed");
    assert!(verify_batch_proof_wasm(&tree, root, &decoded_compressed));
}

#[test]
fn vector_fold_compressed_round_trip() {
    let mut tree = Tree::new(ModeHasher {
        mode: HashFunction::Gemini,
    });
    let key = get_tree_key(HEADER_SUBTREE, &[0x09; 32], 9);
    tree.insert(&key, val(99)).expect("insert should succeed");

    let proof = build_vector_fold_proof(&tree, &key, ProofMode::GeminiHash)
        .expect("vector fold proof generation should succeed");
    let encoded =
        encode_vector_fold_proof_compressed(&proof).expect("compressed encode should succeed");
    let decoded =
        decode_vector_fold_proof_compressed(&encoded).expect("compressed decode should succeed");
    assert!(verify_vector_fold_proof(&decoded));
}

#[test]
fn compressed_decoders_reject_corrupted_payloads() {
    let bad = vec![0x00u8, 0x01, 0x02, 0x03, 0x04];

    assert!(decode_batch_proof_compressed(&bad).is_err());
    assert!(decode_vector_fold_proof_compressed(&bad).is_err());
}
