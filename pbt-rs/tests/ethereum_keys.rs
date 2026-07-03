use pbt_rs::{
    compute_execution_root_commitment,
    compute_vector_fold_commitment,
    get_header_stem_key,
    HashFunction,
};

#[test]
fn header_stem_key_has_expected_shape() {
    let address = [0xABu8; 32];
    let key = get_header_stem_key(&address);

    assert_eq!(key.len(), 33);
    assert_eq!(key[0], 0);
}

#[test]
fn execution_commitment_is_deterministic_and_mode_separated() {
    let root = [0x11u8; 32];
    let c1 = compute_execution_root_commitment(root, HashFunction::Blake3);
    let c2 = compute_execution_root_commitment(root, HashFunction::Blake3);
    let c3 = compute_execution_root_commitment(root, HashFunction::Gemini);

    assert_eq!(c1, c2);
    assert_ne!(c1, c3);
}

#[test]
fn vector_fold_commitment_changes_with_stem_count() {
    let root = [0xAAu8; 32];
    let c1 = compute_vector_fold_commitment(root, HashFunction::Gemini, 2);
    let c2 = compute_vector_fold_commitment(root, HashFunction::Gemini, 3);

    assert_ne!(c1, c2);
}
