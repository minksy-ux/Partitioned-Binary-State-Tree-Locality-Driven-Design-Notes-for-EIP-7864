use pbt_rs::{Blake3Hasher, Tree};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process;

#[derive(Debug, Deserialize)]
struct Suite {
    schema_version: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    operations: Vec<Operation>,
    reads: Vec<String>,
    proof_queries: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Operation {
    op: String,
    key: String,
    value: Option<String>,
}

#[derive(Debug, Serialize)]
struct SuiteResult {
    schema_version: String,
    cases: Vec<CaseResult>,
}

#[derive(Debug, Serialize)]
struct CaseResult {
    id: String,
    root: String,
    reads: BTreeMap<String, String>,
    proofs: BTreeMap<String, ProofResult>,
}

#[derive(Debug, Serialize)]
struct ProofResult {
    value: String,
    valid: bool,
}

fn decode_hex(data: &str) -> Result<Vec<u8>, String> {
    hex::decode(data).map_err(|err| format!("invalid hex {}: {}", data, err))
}

fn decode_hex_32(data: &str) -> Result<[u8; 32], String> {
    let decoded = decode_hex(data)?;
    if decoded.len() != 32 {
        return Err(format!("expected 32-byte value, got {} bytes", decoded.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

fn run_case(case: &Case) -> Result<CaseResult, String> {
    let mut tree = Tree::new(Blake3Hasher);

    for operation in &case.operations {
        let key = decode_hex(&operation.key)?;
        if key.len() < 2 {
            return Err(format!("key must be >= 2 bytes: {}", operation.key));
        }
        match operation.op.as_str() {
            "insert" => {
                let value_hex = operation
                    .value
                    .as_ref()
                    .ok_or_else(|| "insert operation missing value".to_string())?;
                let value = decode_hex_32(value_hex)?;
                tree.insert(&key, value)?;
            }
            "delete" => {
                tree.delete(&key)?;
            }
            other => {
                return Err(format!("unsupported operation: {}", other));
            }
        }
    }

    let mut reads = BTreeMap::<String, String>::new();
    for key_hex in &case.reads {
        let key = decode_hex(key_hex)?;
        let value = tree.get(&key)?;
        reads.insert(key_hex.clone(), to_hex(&value));
    }

    let root = tree.root_hash();
    let mut proofs = BTreeMap::<String, ProofResult>::new();
    for key_hex in &case.proof_queries {
        let key = decode_hex(key_hex)?;
        let proof = tree.get_proof(&key)?;
        let valid = tree.verify_proof(root, &proof);
        proofs.insert(
            key_hex.clone(),
            ProofResult {
                value: to_hex(&proof.value),
                valid,
            },
        );
    }

    Ok(CaseResult {
        id: case.id.clone(),
        root: to_hex(&root),
        reads,
        proofs,
    })
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err("usage: conformance_case <suite_json_path>".to_string());
    }

    let input = fs::read_to_string(&args[1]).map_err(|err| format!("read failed: {}", err))?;
    let suite: Suite = serde_json::from_str(&input).map_err(|err| format!("invalid json: {}", err))?;
    if suite.schema_version != "1.0.0" {
        return Err(format!("unsupported schema version: {}", suite.schema_version));
    }

    let mut cases = Vec::<CaseResult>::new();
    for case in &suite.cases {
        cases.push(run_case(case)?);
    }

    let output = SuiteResult {
        schema_version: suite.schema_version,
        cases,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
    );
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("conformance_case: {}", err);
        process::exit(1);
    }
}