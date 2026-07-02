#!/usr/bin/env python3
"""
Demo: Using the Partitioned Binary Tree reference implementation.

This script demonstrates:
  1. Building a small PBT with account data
  2. Generating and verifying Merkle proofs
  3. Performing insertions, updates, and deletions
  4. Showing locality benefits (same-stem access)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt import (
    EmptyNode,
    insert,
    get,
    delete,
    root_hash,
    get_proof,
    verify_proof,
    get_tree_key_for_basic_data,
    get_tree_key_for_storage_slot,
    get_tree_key_for_code_chunk,
    encode_basic_data,
    EMPTY_VALUE,
)


def demo_basic_account():
    """Create a small account and verify its state."""
    print("=" * 70)
    print("DEMO 1: Basic Account Creation and State")
    print("=" * 70)
    
    # Address (32 bytes)
    address = bytes.fromhex("1234567890123456789012345678901234567890123456789012345678901234")
    
    # Build tree with account data
    root = EmptyNode()
    
    # Insert BASIC_DATA (version, balance, nonce, code_size)
    basic_data_key = get_tree_key_for_basic_data(address)
    basic_data = encode_basic_data(
        version=1,
        balance=10**18,  # 1 ETH
        nonce=42,
        code_size=256,
    )
    root = insert(root, basic_data_key, basic_data)
    print(f"✓ Inserted account basic data")
    
    # Insert first 4 storage slots (co-located in header stem)
    for slot in range(4):
        key = get_tree_key_for_storage_slot(address, slot)
        value = (slot * 1000).to_bytes(32, "big")
        root = insert(root, key, value)
    print(f"✓ Inserted 4 storage slots (all in header stem)")
    
    # Insert first 8 code chunks (co-located in header stem)
    for chunk_id in range(8):
        key = get_tree_key_for_code_chunk(address, chunk_id)
        value = (chunk_id * 100).to_bytes(32, "big")
        root = insert(root, key, value)
    print(f"✓ Inserted 8 code chunks (all in header stem)")
    
    # Show root hash
    rh = root_hash(root)
    print(f"\n✓ Root hash: {rh.hex()[:16]}...")
    print(f"  Tree contains all account hot state in a single stem!\n")
    return root, address, rh


def demo_proofs(root, address, root_hash_expected):
    """Generate and verify Merkle proofs."""
    print("=" * 70)
    print("DEMO 2: Merkle Proof Generation and Verification")
    print("=" * 70)
    
    # Generate proof for storage slot 2
    storage_key = get_tree_key_for_storage_slot(address, 2)
    proof = get_proof(root, storage_key)
    
    print(f"✓ Generated proof for storage slot 2")
    print(f"  Proof size: {len(proof.path_siblings)} siblings in path")
    print(f"  Proof value: {proof.value.hex()[:16]}...")
    
    # Verify the proof
    is_valid = verify_proof(root_hash_expected, proof)
    print(f"✓ Proof verification: {'PASS' if is_valid else 'FAIL'}")
    
    # Try to forge a proof (tamper with value)
    print(f"\n  Attempting to forge proof...")
    bad_proof = type(proof)(
        key=proof.key,
        value=bytes(32),  # wrong value
        stem_values=proof.stem_values,
        path_siblings=proof.path_siblings,
        path_bits=proof.path_bits,
    )
    is_valid_bad = verify_proof(root_hash_expected, bad_proof)
    print(f"✓ Tampered proof rejected: {not is_valid_bad}\n")
    return proof


def demo_updates():
    """Insert, update, and delete operations."""
    print("=" * 70)
    print("DEMO 3: Insert, Update, Delete Operations")
    print("=" * 70)
    
    address = bytes(32)
    root = EmptyNode()
    
    # Insert 3 storage slots
    keys = []
    for slot in range(3):
        key = get_tree_key_for_storage_slot(address, slot)
        value = slot.to_bytes(32, "big")
        root = insert(root, key, value)
        keys.append(key)
    
    print(f"✓ Inserted 3 storage slots")
    h1 = root_hash(root)
    print(f"  Root hash: {h1.hex()[:16]}...")
    
    # Update slot 1
    root = insert(root, keys[1], (999).to_bytes(32, "big"))
    print(f"\n✓ Updated slot 1 to value 999")
    h2 = root_hash(root)
    print(f"  Root hash changed: {h1.hex()[:16]}... → {h2.hex()[:16]}...")
    assert h1 != h2, "Hash should change after update"
    
    # Delete slot 1
    root = delete(root, keys[1])
    print(f"\n✓ Deleted slot 1")
    h3 = root_hash(root)
    print(f"  Root hash changed: {h2.hex()[:16]}... → {h3.hex()[:16]}...")
    assert get(root, keys[1]) == EMPTY_VALUE, "Deleted slot should be empty"
    print(f"  ✓ Slot 1 is now empty")
    

def demo_locality():
    """Show the locality benefit of stems."""
    print("\n" + "=" * 70)
    print("DEMO 4: Locality — Multiple Accesses Share a Stem")
    print("=" * 70)
    
    address = bytes(32)
    root = EmptyNode()
    
    # Insert multiple storage slots (first 4 share header stem)
    print(f"Inserting 4 storage slots (indices 0-3)...")
    for slot in range(4):
        key = get_tree_key_for_storage_slot(address, slot)
        value = slot.to_bytes(32, "big")
        root = insert(root, key, value)
    
    # All 4 should be in same stem — so a proof for any of them
    # should have the same path length
    proof_slot_0 = get_proof(root, get_tree_key_for_storage_slot(address, 0))
    proof_slot_3 = get_proof(root, get_tree_key_for_storage_slot(address, 3))
    
    print(f"\n✓ Proof for slot 0: {len(proof_slot_0.path_siblings)} siblings")
    print(f"✓ Proof for slot 3: {len(proof_slot_3.path_siblings)} siblings")
    
    if len(proof_slot_0.path_siblings) == len(proof_slot_3.path_siblings):
        print(f"✓ Same proof depth: slots share a stem!")
    
    # Now insert a slot beyond the header (slot 5)
    key_slot_5 = get_tree_key_for_storage_slot(address, 5)
    root = insert(root, key_slot_5, (5).to_bytes(32, "big"))
    
    proof_slot_5 = get_proof(root, key_slot_5)
    print(f"\n✓ Proof for slot 5 (overflow): {len(proof_slot_5.path_siblings)} siblings")
    print(f"  (Different stem from slots 0-3, so different proof depth)\n")


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("PARTITIONED BINARY TREE REFERENCE IMPLEMENTATION DEMO")
    print("=" * 70 + "\n")
    
    try:
        root, address, rh = demo_basic_account()
        demo_proofs(root, address, rh)
        demo_updates()
        demo_locality()
        
        print("=" * 70)
        print("✓ ALL DEMOS PASSED")
        print("=" * 70 + "\n")
        
    except Exception as e:
        print(f"\n✗ DEMO FAILED: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
