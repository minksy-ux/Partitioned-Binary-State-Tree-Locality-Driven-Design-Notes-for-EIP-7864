#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFunction {
    Blake3,
    Poseidon2,
    Gemini,
}

fn blake3_hash(input: &[u8]) -> [u8; 32] {
    *blake3::hash(input).as_bytes()
}

fn poseidon2_hash_two(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // Placeholder path until a pinned Poseidon2 crate/API is selected.
    // Domain separation prevents accidental equivalence with Blake3 mode.
    let mut input = Vec::<u8>::with_capacity(10 + 64);
    input.extend_from_slice(b"poseidon2:");
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    blake3_hash(&input)
}

fn bytes32_to_u64s(value: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, chunk) in value.chunks_exact(8).enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        out[i] = u64::from_le_bytes(word);
    }
    out
}

fn u64s_to_bytes32(value: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in value.iter().enumerate() {
        let bytes = word.to_le_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    out
}

fn gemini_mix_round(state: &mut [u64; 8], round: u64) {
    const C0: u64 = 0x9E37_79B9_7F4A_7C15;
    const C1: u64 = 0xBF58_476D_1CE4_E5B9;
    const C2: u64 = 0x94D0_49BB_1331_11EB;

    for (i, slot) in state.iter_mut().enumerate() {
        let tweak = (round.wrapping_add(i as u64)).wrapping_mul(C0);
        *slot = slot.wrapping_add(tweak).rotate_left((11 + i as u32) % 64);
    }

    for i in 0..4 {
        let a = state[i];
        let b = state[i + 4];
        state[i] = a.wrapping_add(b).wrapping_mul(C1.rotate_left((i as u32) * 7));
        state[i + 4] = (a ^ b).wrapping_add(C2.rotate_left((i as u32) * 9));
    }

    state.rotate_left(1);
}

fn gemini_hash_two(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let l = bytes32_to_u64s(left);
    let r = bytes32_to_u64s(right);
    let mut state = [
        l[0],
        l[1],
        l[2],
        l[3],
        r[0],
        r[1],
        r[2],
        r[3],
    ];

    // Prototype binary-friendly compressor for PBT folding pipelines.
    for round in 0..10 {
        gemini_mix_round(&mut state, round);
    }

    let out = [
        state[0] ^ state[4],
        state[1] ^ state[5],
        state[2] ^ state[6],
        state[3] ^ state[7],
    ];
    u64s_to_bytes32(out)
}

pub fn tree_hash(left: &[u8; 32], right: &[u8; 32], mode: HashFunction) -> [u8; 32] {
    match mode {
        HashFunction::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(left);
            hasher.update(right);
            *hasher.finalize().as_bytes()
        }
        HashFunction::Poseidon2 => poseidon2_hash_two(left, right),
        HashFunction::Gemini => gemini_hash_two(left, right),
    }
}

pub fn hash_bytes(input: &[u8], mode: HashFunction) -> [u8; 32] {
    match mode {
        HashFunction::Blake3 => blake3_hash(input),
        HashFunction::Poseidon2 => {
            let mut tagged = Vec::<u8>::with_capacity(10 + input.len());
            tagged.extend_from_slice(b"poseidon2:");
            tagged.extend_from_slice(input);
            blake3_hash(&tagged)
        }
        HashFunction::Gemini => {
            let mut acc = [0u8; 32];
            acc[..8].copy_from_slice(b"gemini:v");
            let mut chunk = [0u8; 32];

            for part in input.chunks(32) {
                chunk.fill(0);
                chunk[..part.len()].copy_from_slice(part);
                acc = gemini_hash_two(&acc, &chunk);
            }
            acc
        }
    }
}

pub fn hash_stem(prefix: &[u8], values: &[[u8; 32]; 256], mode: HashFunction) -> [u8; 32] {
    if mode == HashFunction::Gemini {
        let mut prefix_block = [0u8; 32];
        let copy_len = prefix.len().min(32);
        prefix_block[..copy_len].copy_from_slice(&prefix[..copy_len]);

        let mut level = values.to_vec();
        while level.len() > 1 {
            let mut next = Vec::<[u8; 32]>::with_capacity(level.len() / 2);
            for pair in level.chunks_exact(2) {
                next.push(gemini_hash_two(&pair[0], &pair[1]));
            }
            level = next;
        }

        return gemini_hash_two(&prefix_block, &level[0]);
    }

    let mut input = Vec::<u8>::with_capacity(12 + prefix.len() + values.len() * 32);
    input.extend_from_slice(b"PBT:STEM:v1");
    input.extend_from_slice(prefix);
    for value in values {
        input.extend_from_slice(value);
    }
    hash_bytes(&input, mode)
}
