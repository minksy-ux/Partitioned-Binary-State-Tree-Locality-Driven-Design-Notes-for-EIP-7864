use pbt_rs::{
    get_tree_key,
    Blake3Hasher,
    Tree,
    EMPTY_VALUE,
    HEADER_SUBTREE,
};
use proptest::prelude::*;
fn val(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

fn key_from_parts(stem_byte: u8, subindex: u8) -> Vec<u8> {
    let stem = vec![stem_byte; 32];
    get_tree_key(HEADER_SUBTREE, &stem, subindex)
}

proptest! {
    #[test]
    fn property_insert_get_proof_roundtrip(
        storage_type in 0u8..=2u8,
        stem_byte in any::<u8>(),
        subindex in 0u8..=255u8,
        payload in any::<u64>(),
    ) {
        let mut tree = Tree::new(Blake3Hasher);
        let stem = vec![stem_byte; 32];
        let key = get_tree_key(HEADER_SUBTREE + storage_type, &stem, subindex);
        let value = val(payload);

        tree.insert(&key, value).expect("insert should succeed");
        let got = tree.get(&key).expect("get should succeed");
        prop_assert_eq!(got, value);

        let root = tree.root_hash();
        let proof = tree.get_proof(&key).expect("proof generation should succeed");
        prop_assert!(tree.verify_proof(root, &proof));
    }

    #[test]
    fn property_absent_key_proof_verifies_to_empty(
        stem_byte in any::<u8>(),
        present_subindex in any::<u8>(),
        absent_subindex in any::<u8>(),
        payload in any::<u64>(),
    ) {
        prop_assume!(present_subindex != absent_subindex);

        let mut tree = Tree::new(Blake3Hasher);
        let present_key = key_from_parts(stem_byte, present_subindex);
        let absent_key = key_from_parts(stem_byte, absent_subindex);
        let present_value = val(payload);

        tree.insert(&present_key, present_value).expect("insert should succeed");
        let root = tree.root_hash();

        let absent_proof = tree.get_proof(&absent_key).expect("proof generation should succeed");
        prop_assert_eq!(absent_proof.value, EMPTY_VALUE);
        prop_assert!(tree.verify_proof(root, &absent_proof));
    }
}
