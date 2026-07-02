#!/usr/bin/env python3
"""
CLI tool for the Partitioned Binary Tree.

Provides interactive commands to build, inspect, and verify PBT operations.

Usage:
  python cli.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt import (
    EmptyNode, InternalNode, StemNode,
    insert, get, delete, root_hash, get_proof, verify_proof,
    get_tree_key_for_basic_data, get_tree_key_for_storage_slot, 
    get_tree_key_for_code_chunk, encode_basic_data,
    EMPTY_VALUE, STEM_SUBTREE_WIDTH,
)
from pbt.tree import split_key


class PBTSession:
    """Interactive PBT session."""
    
    def __init__(self):
        self.root = EmptyNode()
        self.address = bytes(32)  # default zero address
        self.recent_proofs = {}
    
    def help(self):
        """Print help."""
        help_text = """
PBT CLI Commands:
  help              - show this help
  new               - create a new empty tree
  addr <hex32>      - set the current address (32 hex bytes)
  set <key> <val>   - insert key->value (key and val as hex)
  get <key>         - retrieve value at key (hex)
  del <key>         - delete key
  root              - show current root hash (hex)
  info              - show tree statistics
  proof <key>       - generate proof for key
  verify <key>      - verify proof for key
  proof_list        - show recent proofs
  quit / exit       - exit the CLI

Example session:
  > new
  > addr 0000000000000000000000000000000000000000000000000000000000000001
  > set 000000000000000000000000000000000000000000000000000000000000000100 1000000000000000000000000000000000000000000000000000000000000000
  > get 000000000000000000000000000000000000000000000000000000000000000100
  > root
  > proof 000000000000000000000000000000000000000000000000000000000000000100
  > quit
"""
        print(help_text)
    
    def cmd_new(self, args):
        """Create a new tree."""
        self.root = EmptyNode()
        self.recent_proofs = {}
        print("✓ Tree reset to EmptyNode")
    
    def cmd_addr(self, args):
        """Set the current address."""
        if not args:
            print(f"Current address: {self.address.hex()}")
            return
        try:
            self.address = bytes.fromhex(args[0])
            if len(self.address) != 32:
                print("✗ Address must be 32 bytes (64 hex chars)")
                self.address = bytes(32)
                return
            print(f"✓ Address set to {self.address.hex()[:16]}...")
        except ValueError:
            print("✗ Invalid hex string")
    
    def cmd_set(self, args):
        """Insert a key-value pair."""
        if len(args) < 2:
            print("Usage: set <key> <value> (as hex)")
            return
        try:
            key = bytes.fromhex(args[0])
            value = bytes.fromhex(args[1])
            if len(value) != 32:
                print("✗ Value must be 32 bytes (64 hex chars)")
                return
            self.root = insert(self.root, key, value)
            print(f"✓ Inserted {key.hex()[:16]}... = {value.hex()[:16]}...")
        except ValueError as e:
            print(f"✗ {e}")
    
    def cmd_get(self, args):
        """Retrieve a value."""
        if not args:
            print("Usage: get <key> (as hex)")
            return
        try:
            key = bytes.fromhex(args[0])
            value = get(self.root, key)
            if value == EMPTY_VALUE:
                print(f"✗ Key not found (returned EMPTY_VALUE)")
            else:
                print(f"✓ {key.hex()[:16]}... = {value.hex()[:16]}...")
        except ValueError as e:
            print(f"✗ {e}")
    
    def cmd_del(self, args):
        """Delete a key."""
        if not args:
            print("Usage: del <key> (as hex)")
            return
        try:
            key = bytes.fromhex(args[0])
            self.root = delete(self.root, key)
            print(f"✓ Deleted {key.hex()[:16]}...")
        except ValueError as e:
            print(f"✗ {e}")
    
    def cmd_root(self, args):
        """Show root hash."""
        rh = root_hash(self.root)
        print(f"Root hash: {rh.hex()}")
    
    def cmd_info(self, args):
        """Show tree info."""
        def count_nodes(n):
            if isinstance(n, EmptyNode):
                return 0, 0, 0
            if isinstance(n, StemNode):
                return 1, 0, sum(1 for v in n.values if v != EMPTY_VALUE)
            # InternalNode
            stems_l, internals_l, leaves_l = count_nodes(n.left)
            stems_r, internals_r, leaves_r = count_nodes(n.right)
            return (stems_l + stems_r, 
                   1 + internals_l + internals_r,
                   leaves_l + leaves_r)
        
        stems, internals, leaves = count_nodes(self.root)
        print(f"Tree info:")
        print(f"  Stems: {stems}")
        print(f"  Internal nodes: {internals}")
        print(f"  Leaves (non-empty): {leaves}")
        print(f"  Root: {root_hash(self.root).hex()[:16]}...")
    
    def cmd_proof(self, args):
        """Generate a proof."""
        if not args:
            print("Usage: proof <key> (as hex)")
            return
        try:
            key = bytes.fromhex(args[0])
            proof = get_proof(self.root, key)
            self.recent_proofs[key.hex()] = proof
            print(f"✓ Generated proof for {key.hex()[:16]}...")
            print(f"  Proof depth: {len(proof.path_siblings)} siblings")
            print(f"  Value: {proof.value.hex()[:16]}...")
            rh = root_hash(self.root)
            is_valid = verify_proof(rh, proof)
            print(f"  Valid: {'YES' if is_valid else 'NO'}")
        except ValueError as e:
            print(f"✗ {e}")
    
    def cmd_verify(self, args):
        """Verify a proof."""
        if not args:
            print("Usage: verify <key> (as hex)")
            return
        try:
            key_hex = args[0]
            key = bytes.fromhex(key_hex)
            if key_hex not in self.recent_proofs:
                print(f"✗ No proof stored for {key_hex[:16]}...")
                print(f"   Use 'proof <key>' first.")
                return
            proof = self.recent_proofs[key_hex]
            rh = root_hash(self.root)
            is_valid = verify_proof(rh, proof)
            print(f"Proof for {key_hex[:16]}... : {'VALID ✓' if is_valid else 'INVALID ✗'}")
        except ValueError as e:
            print(f"✗ {e}")
    
    def cmd_proof_list(self, args):
        """List recent proofs."""
        if not self.recent_proofs:
            print("No proofs stored yet. Use 'proof <key>' to generate.")
            return
        for key_hex, proof in self.recent_proofs.items():
            print(f"  {key_hex[:16]}... (depth={len(proof.path_siblings)})")
    
    def process_command(self, line):
        """Process a single command."""
        parts = line.strip().split()
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        commands = {
            'help': self.help,
            'new': self.cmd_new,
            'addr': self.cmd_addr,
            'set': self.cmd_set,
            'get': self.cmd_get,
            'del': self.cmd_del,
            'root': self.cmd_root,
            'info': self.cmd_info,
            'proof': self.cmd_proof,
            'verify': self.cmd_verify,
            'proof_list': self.cmd_proof_list,
        }
        
        if cmd in commands:
            try:
                commands[cmd](args)
            except Exception as e:
                print(f"✗ Error: {e}")
        else:
            print(f"Unknown command '{cmd}'. Type 'help' for available commands.")
    
    def run(self):
        """Run the interactive session."""
        print("Partitioned Binary Tree (EIP-7864) CLI")
        print("Type 'help' for commands, 'quit' or 'exit' to exit.\n")
        
        while True:
            try:
                line = input("pbt> ").strip()
                if not line:
                    continue
                if line in ('quit', 'exit'):
                    print("Goodbye!")
                    break
                self.process_command(line)
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except EOFError:
                print("\nExiting...")
                break


if __name__ == "__main__":
    session = PBTSession()
    session.run()
