use pbt_rs::{
    gemini_compress,
    gemini_compress_with_params,
    hash_stem,
    tree_hash,
    GeminiField,
    GeminiParameters,
    HashFunction,
};

#[test]
fn tree_hash_blake3_and_poseidon2_modes_return_32_bytes() {
    let left = [0x11u8; 32];
    let right = [0x22u8; 32];

    let blake3 = tree_hash(&left, &right, HashFunction::Blake3);
    let poseidon2 = tree_hash(&left, &right, HashFunction::Poseidon2);
    let gemini = tree_hash(&left, &right, HashFunction::Gemini);

    assert_eq!(blake3.len(), 32);
    assert_eq!(poseidon2.len(), 32);
    assert_eq!(gemini.len(), 32);
    assert_ne!(blake3, poseidon2);
    assert_ne!(blake3, gemini);
    assert_ne!(poseidon2, gemini);
}

#[test]
fn hash_stem_supports_fixed_256_leaf_array() {
    let mut values = [[0u8; 32]; 256];
    values[0] = [0xAA; 32];
    values[255] = [0xBB; 32];
    let prefix = vec![0x01u8; 33];

    let h1 = hash_stem(&prefix, &values, HashFunction::Blake3);
    let h2 = hash_stem(&prefix, &values, HashFunction::Poseidon2);
    let h3 = hash_stem(&prefix, &values, HashFunction::Gemini);

    assert_eq!(h1.len(), 32);
    assert_eq!(h2.len(), 32);
    assert_eq!(h3.len(), 32);
    assert_ne!(h1, h2);
    assert_ne!(h1, h3);
    assert_ne!(h2, h3);
}

#[test]
fn gemini_compress_is_deterministic_and_field_tunable() {
    let left = [0x3Cu8; 32];
    let right = [0xC3u8; 32];

    let d1 = gemini_compress(&left, &right);
    let d2 = gemini_compress(&left, &right);
    assert_eq!(d1, d2);

    let babybear = gemini_compress_with_params(
        &left,
        &right,
        GeminiParameters {
            field: GeminiField::BabyBear,
            rounds: 10,
        },
    );
    assert_ne!(d1, babybear);
}
