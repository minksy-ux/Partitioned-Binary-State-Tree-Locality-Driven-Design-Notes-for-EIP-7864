#!/usr/bin/env python3
"""
CLI tool for the Partitioned Binary Tree.

Provides interactive commands to build, inspect, and verify PBT operations.

Usage:
  python cli.py
    python cli.py rpc_demo
"""

import sys
import os
from copy import deepcopy
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt import (
    EmptyNode, StemNode,
    insert, get, delete, root_hash, get_proof, verify_proof,
    get_tree_key_for_basic_data, encode_basic_data,
    EMPTY_VALUE,
    StemWitnessPacket,
    make_eth_getVerifiedProof_result,
    verify_eth_getVerifiedProof_result,
    make_eth_getStemWitness_result,
    verify_eth_getStemWitness_result,
    default_policy,
    default_release_artifacts,
    FormalVerificationDashboard,
)


class PBTSession:
    """Interactive PBT session."""
    
    def __init__(self):
        self.root = EmptyNode()
        self.address = bytes(32)  # default zero address
        self.recent_proofs = {}

    @staticmethod
    def _parse_hex_arg(value: str, field_name: str, expected_len: int | None = None) -> bytes:
        try:
            parsed = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be valid hex") from exc
        if expected_len is not None and len(parsed) != expected_len:
            raise ValueError(
                f"{field_name} must be {expected_len} bytes ({expected_len * 2} hex chars)"
            )
        return parsed
    
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
    rpc_demo          - run verified-RPC wallet-status simulation
    formal_dashboard  - print formal verification readiness dashboard
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
            self.address = self._parse_hex_arg(args[0], "address", expected_len=32)
            print(f"✓ Address set to {self.address.hex()[:16]}...")
        except ValueError:
            print("✗ Address must be valid 32-byte hex")
    
    def cmd_set(self, args):
        """Insert a key-value pair."""
        if len(args) < 2:
            print("Usage: set <key> <value> (as hex)")
            return
        try:
            key = self._parse_hex_arg(args[0], "key")
            value = self._parse_hex_arg(args[1], "value", expected_len=32)
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
            key = self._parse_hex_arg(args[0], "key")
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
            key = self._parse_hex_arg(args[0], "key")
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
            key = self._parse_hex_arg(args[0], "key")
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
            key = self._parse_hex_arg(args[0], "key")
            key_hex = key.hex()
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

    @staticmethod
    def _flip_last_hex_nibble(hex_value: str) -> str:
        if not hex_value.startswith("0x") or len(hex_value) <= 2:
            raise ValueError("expected 0x-prefixed hex string")
        last = hex_value[-1]
        return hex_value[:-1] + ("0" if last != "0" else "1")

    def cmd_rpc_demo(self, args):
        """Run a wallet-like verified/unverified status simulation."""
        key = get_tree_key_for_basic_data(self.address)
        value = encode_basic_data(version=1, balance=1000, nonce=7, code_size=0)
        demo_root = insert(EmptyNode(), key, value)
        trusted_root = root_hash(demo_root)
        proof = get_proof(demo_root, key)

        print("Wallet status flow for eth_getVerifiedProof")
        print("  - status: UNVERIFIED (response received)")
        verified_payload = make_eth_getVerifiedProof_result(
            provider="provider-a",
            block_number=123,
            block_hash=b"h" * 32,
            state_root=trusted_root,
            key=key,
            value=value,
            proof=proof,
        )
        verify_ok = verify_eth_getVerifiedProof_result(
            verified_payload,
            expected_state_root=trusted_root,
        )
        print(
            f"  - status: {'VERIFIED' if verify_ok.accepted else 'UNVERIFIED'} "
            f"({verify_ok.reason})"
        )

        bad_proof_payload = deepcopy(verified_payload)
        bad_proof_payload["state"]["value"] = "0xxyz"
        verify_bad = verify_eth_getVerifiedProof_result(
            bad_proof_payload,
            expected_state_root=trusted_root,
        )
        print(
            f"  - tampered payload: {'VERIFIED' if verify_bad.accepted else 'UNVERIFIED'} "
            f"({verify_bad.reason})"
        )

        packet = StemWitnessPacket(
            epoch=1,
            block_number=123,
            block_root=trusted_root,
            stem_prefix=key[:-1],
            key=key,
            value=value,
            proof=proof,
            bucket_id=2,
        )
        print("Wallet status flow for eth_getStemWitness")
        print("  - status: UNVERIFIED (response received)")
        stem_payload = make_eth_getStemWitness_result(
            provider="provider-a",
            block_hash=b"b" * 32,
            packet=packet,
        )
        stem_ok = verify_eth_getStemWitness_result(
            stem_payload,
            expected_state_root=trusted_root,
        )
        print(
            f"  - status: {'VERIFIED' if stem_ok.accepted else 'UNVERIFIED'} "
            f"({stem_ok.reason})"
        )

        bad_stem_payload = deepcopy(stem_payload)
        wire = bad_stem_payload["stemWitness"]["packetWire"]
        bad_stem_payload["stemWitness"]["packetWire"] = self._flip_last_hex_nibble(wire)
        stem_bad = verify_eth_getStemWitness_result(
            bad_stem_payload,
            expected_state_root=trusted_root,
        )
        print(
            f"  - tampered payload: {'VERIFIED' if stem_bad.accepted else 'UNVERIFIED'} "
            f"({stem_bad.reason})"
        )

    def cmd_formal_dashboard(self, args):
        """Print a formal verification dashboard snapshot."""
        artifacts = default_release_artifacts()
        dashboard = FormalVerificationDashboard(default_policy())
        snapshot = dashboard.build_snapshot(artifacts)
        print(dashboard.render_markdown(snapshot, include_phone_user_story=True))
    
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
            'rpc_demo': self.cmd_rpc_demo,
            'formal_dashboard': self.cmd_formal_dashboard,
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
    one_shot_commands = {
        "rpc_demo": session.cmd_rpc_demo,
        "formal_dashboard": session.cmd_formal_dashboard,
    }
    if len(sys.argv) > 1:
        cmd = sys.argv[1].strip().lower()
        if cmd in one_shot_commands:
            one_shot_commands[cmd]([])
        elif cmd in ("help", "-h", "--help"):
            session.help()
        else:
            print(f"Unknown one-shot command '{cmd}'.")
            print("Supported one-shot commands: rpc_demo, formal_dashboard")
            print("Use 'python cli.py' for interactive mode.")
            sys.exit(2)
    else:
        session.run()
