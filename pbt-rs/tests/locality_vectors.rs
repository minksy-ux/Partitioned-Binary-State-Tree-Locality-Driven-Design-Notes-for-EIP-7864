use pbt_rs::{
    get_tree_key_for_storage_slot,
    Blake3Hasher,
    Tree,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct LocalityGroup {
    name: String,
    slots: Vec<usize>,
    expect_same_path: bool,
}

#[derive(Debug, Deserialize)]
struct LocalityFixture {
    address_hex: String,
    groups: Vec<LocalityGroup>,
    cross_group_expect_different_path: bool,
}

fn parse_hex_32(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).expect("valid hex required");
    assert_eq!(bytes.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn val(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

#[test]
fn locality_vector_path_shapes_match_expectations() {
    let fixture_text = include_str!("vectors/locality_vector.json");
    let fixture: LocalityFixture =
        serde_json::from_str(fixture_text).expect("fixture json should parse");
    let address = parse_hex_32(&fixture.address_hex);

    let mut tree = Tree::new(Blake3Hasher);
    let mut counter = 1u64;
    for group in &fixture.groups {
        for slot in &group.slots {
            let key = get_tree_key_for_storage_slot(address, *slot);
            tree.insert(&key, val(counter)).expect("insert should succeed");
            counter += 1;
        }
    }

    let mut representative_paths = Vec::<(String, Vec<u8>, usize)>::new();
    for group in &fixture.groups {
        let mut paths = Vec::<(Vec<u8>, usize)>::new();
        for slot in &group.slots {
            let key = get_tree_key_for_storage_slot(address, *slot);
            let proof = tree.get_proof(&key).expect("proof generation should succeed");
            paths.push((proof.path_bits.clone(), proof.path_siblings.len()));
        }

        if group.expect_same_path {
            let first = paths.first().expect("group must include slots").clone();
            for path in paths.iter().skip(1) {
                assert_eq!(path.0, first.0, "group {} path bits mismatch", group.name);
                assert_eq!(path.1, first.1, "group {} path depth mismatch", group.name);
            }
        }

        representative_paths.push((group.name.clone(), paths[0].0.clone(), paths[0].1));
    }

    if fixture.cross_group_expect_different_path {
        for i in 0..representative_paths.len() {
            for j in (i + 1)..representative_paths.len() {
                let left = &representative_paths[i];
                let right = &representative_paths[j];
                assert!(
                    left.1 != right.1 || left.2 != right.2,
                    "expected groups {} and {} to differ in path shape",
                    left.0,
                    right.0,
                );
            }
        }
    }
}
