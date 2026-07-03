use pbt_rs::{get_tree_key, Blake3Hasher, Tree, HEADER_SUBTREE};

fn val(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

fn main() {
    // Lightweight benchmark skeleton without external harness dependency.
    let mut tree = Tree::new(Blake3Hasher);
    let total = 10_000usize;

    let start = std::time::Instant::now();
    for i in 0..total {
        let mut stem = [0u8; 32];
        stem[31] = (i % 251) as u8;
        let key = get_tree_key(HEADER_SUBTREE, &stem, (i % 256) as u8);
        tree.insert(&key, val(i as u64)).expect("insert should succeed");
    }
    let elapsed = start.elapsed();
    println!(
        "insert throughput: {:.2} ops/s",
        total as f64 / elapsed.as_secs_f64()
    );

    let root = tree.root_hash();
    println!("root hash prefix: {:02x}{:02x}{:02x}{:02x}", root[0], root[1], root[2], root[3]);

    let mut sample_keys = Vec::<Vec<u8>>::new();
    for i in 0..200usize {
        let mut stem = [0u8; 32];
        stem[31] = (i % 251) as u8;
        sample_keys.push(get_tree_key(HEADER_SUBTREE, &stem, (i % 256) as u8));
    }

    let mut total_single = 0usize;
    let mut worst_single = 0usize;
    for key in &sample_keys {
        let proof = tree.get_proof(key).expect("proof generation should succeed");
        let encoded = bincode::serialize(&proof).expect("proof encoding should succeed");
        let size = encoded.len();
        total_single += size;
        if size > worst_single {
            worst_single = size;
        }
    }

    let avg_single = total_single as f64 / sample_keys.len() as f64;
    println!(
        "single proof size: avg={:.2} bytes, worst={} bytes over {} samples",
        avg_single,
        worst_single,
        sample_keys.len()
    );

    let batch = tree
        .get_multi_proof(&sample_keys)
        .expect("batch proof generation should succeed");
    let encoded_batch = bincode::serialize(&batch).expect("batch proof encoding should succeed");
    println!(
        "batch proof size: total={} bytes, amortized_per_key={:.2} bytes",
        encoded_batch.len(),
        encoded_batch.len() as f64 / sample_keys.len() as f64
    );
}
