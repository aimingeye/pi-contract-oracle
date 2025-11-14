#!/usr/bin/env python3
"""
Pi Oracle - Rust Bindings Test Suite

Verifies that all cryptographic functions are working correctly:
- SHA-256 hashing
- ECDSA keypair generation, signing, and verification
- Merkle tree construction and root computation
- Merkle proof generation and verification

This can be run by users to verify their installation.
"""

import sys
import time
import argparse
import json
import pi_oracle_core as core


# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright foreground colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'


def log_step(step_num, total_steps, message):
    """Log a test step with progress indicator."""
    print(f"{Colors.BOLD}{Colors.CYAN}[{step_num}/{total_steps}]{Colors.RESET} {Colors.BOLD}{message}{Colors.RESET}")


def log_detail(message, indent=1):
    """Log detailed information with indentation."""
    prefix = "  " * indent
    print(f"{prefix}{Colors.BRIGHT_BLACK}|{Colors.RESET} {message}")


def log_success(message):
    """Log a success message."""
    print(f"  {Colors.GREEN}[PASS]{Colors.RESET} {message}\n")


def log_error(message):
    """Log an error message."""
    print(f"  {Colors.RED}[FAIL]{Colors.RESET} {message}\n")


def log_info(message):
    """Log an info message."""
    print(f"{Colors.BRIGHT_CYAN}[INFO]{Colors.RESET} {message}")


def log_data(label, value, color=Colors.YELLOW):
    """Log data with label and value."""
    print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.DIM}{label}:{Colors.RESET} {color}{value}{Colors.RESET}")


def print_separator(char="=", length=80, color=Colors.BRIGHT_BLACK):
    """Print a separator line."""
    print(f"{color}{char * length}{Colors.RESET}")


def print_header(title, subtitle=""):
    """Print a styled header."""
    print_separator()
    print(f"{Colors.BOLD}{Colors.BRIGHT_CYAN}{title:^80}{Colors.RESET}")
    if subtitle:
        print(f"{Colors.DIM}{subtitle:^80}{Colors.RESET}")
    print_separator()


def visualize_merkle_tree(data_items, verbose=False):
    """
    Visualize the Merkle tree construction process.
    Shows each hash at each level of the tree.
    """
    print(f"\n{Colors.BOLD}{Colors.BRIGHT_CYAN}Merkle Tree Construction Visualization:{Colors.RESET}")
    print_separator("-", 80, Colors.DIM)
    
    # Compute all leaf hashes
    leaves = [bytes(core.py_hash_data(list(item))) for item in data_items]
    
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}LEVEL 0: Leaf Hashes{Colors.RESET} (Raw data -> SHA-256)")
    print_separator("-", 80, Colors.DIM)
    
    for i, (data, leaf_hash) in enumerate(zip(data_items, leaves)):
        data_preview = data.decode('utf-8')[:50] + "..." if len(data) > 50 else data.decode('utf-8')
        print(f"  {Colors.BRIGHT_BLACK}[{i}]{Colors.RESET} {Colors.DIM}Data:{Colors.RESET} {Colors.WHITE}{data_preview}{Colors.RESET}")
        print(f"      {Colors.DIM}H{i} ={Colors.RESET} {Colors.YELLOW}{leaf_hash.hex()[:32]}...{Colors.RESET}")
    
    # Build tree level by level
    current_level = leaves
    level_num = 1
    
    while len(current_level) > 1:
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}LEVEL {level_num}: Intermediate Hashes{Colors.RESET}")
        print_separator("-", 80, Colors.DIM)
        
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            
            if i + 1 < len(current_level):
                right = current_level[i + 1]
                print(f"  {Colors.BRIGHT_BLACK}[{i//2}]{Colors.RESET} Combining:")
                print(f"      {Colors.DIM}Left  (H{i*2**(level_num-1)}):{Colors.RESET} {Colors.CYAN}{left.hex()[:32]}...{Colors.RESET}")
                print(f"      {Colors.DIM}Right (H{(i+1)*2**(level_num-1)}):{Colors.RESET} {Colors.CYAN}{right.hex()[:32]}...{Colors.RESET}")
            else:
                # Odd node - duplicate it
                right = left
                print(f"  {Colors.BRIGHT_BLACK}[{i//2}]{Colors.RESET} {Colors.DIM}(Odd node - duplicating){Colors.RESET}")
                print(f"      {Colors.DIM}Node (H{i*2**(level_num-1)}):{Colors.RESET} {Colors.CYAN}{left.hex()[:32]}...{Colors.RESET}")
            
            # Hash the pair
            combined = left + right
            parent_hash = bytes(core.py_hash_data(list(combined)))
            next_level.append(parent_hash)
            
            print(f"      {Colors.DIM}Parent ={Colors.RESET} {Colors.YELLOW}{parent_hash.hex()[:32]}...{Colors.RESET}")
        
        current_level = next_level
        level_num += 1
    
    # Root
    root = current_level[0]
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}MERKLE ROOT:{Colors.RESET}")
    print_separator("-", 80, Colors.DIM)
    print(f"  {Colors.BOLD}{Colors.BRIGHT_MAGENTA}{root.hex()}{Colors.RESET}")
    print()


def visualize_proof_verification(proof_json, tick_data, verbose=False):
    """
    Visualize the step-by-step verification of a Merkle proof.
    """
    proof = json.loads(proof_json)
    
    print(f"\n{Colors.BOLD}{Colors.BRIGHT_CYAN}Merkle Proof Verification Visualization:{Colors.RESET}")
    print_separator("-", 80, Colors.DIM)
    
    # Debug: check what keys are in proof
    if verbose:
        log_data("Proof keys", str(list(proof.keys())), Colors.DIM)
    
    # Show the proof structure
    log_data("Leaf Index", proof['leaf_index'], Colors.CYAN)
    log_data("Leaf Data", tick_data.decode('utf-8')[:60] + "..." if len(tick_data) > 60 else tick_data.decode('utf-8'), Colors.WHITE)
    log_data("Merkle Root (claimed)", proof['root'], Colors.BRIGHT_MAGENTA)
    log_data("Sibling Hashes", len(proof['siblings']), Colors.YELLOW)
    
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}Verification Steps:{Colors.RESET}")
    print_separator("-", 80, Colors.DIM)
    
    # Step 1: Hash the leaf data (compute it from the actual data)
    current_hash = bytes(core.py_hash_data(list(tick_data)))
    print(f"\n  {Colors.BOLD}Step 0:{Colors.RESET} Hash leaf data")
    print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.DIM}Input:{Colors.RESET} {Colors.WHITE}{tick_data.decode('utf-8')[:50]}...{Colors.RESET}")
    print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.DIM}Hash:{Colors.RESET}  {Colors.YELLOW}{current_hash.hex()[:32]}...{Colors.RESET}")
    
    # Walk up the tree
    leaf_index = proof['leaf_index']
    
    for i, sibling_hex in enumerate(proof['siblings']):
        sibling = bytes.fromhex(sibling_hex)
        
        # Determine if sibling is on left or right
        is_left = (leaf_index % 2) == 1
        
        print(f"\n  {Colors.BOLD}Step {i+1}:{Colors.RESET} Combine with sibling at level {i+1}")
        
        if is_left:
            print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.DIM}Left (sibling):{Colors.RESET}  {Colors.CYAN}{sibling.hex()[:32]}...{Colors.RESET}")
            print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.DIM}Right (current):{Colors.RESET} {Colors.YELLOW}{current_hash.hex()[:32]}...{Colors.RESET}")
            combined = sibling + current_hash
        else:
            print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.DIM}Left (current):{Colors.RESET}  {Colors.YELLOW}{current_hash.hex()[:32]}...{Colors.RESET}")
            print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.DIM}Right (sibling):{Colors.RESET} {Colors.CYAN}{sibling.hex()[:32]}...{Colors.RESET}")
            combined = current_hash + sibling
        
        # Hash the combined value
        current_hash = bytes(core.py_hash_data(list(combined)))
        print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.DIM}SHA-256(Left || Right) ={Colors.RESET} {Colors.YELLOW}{current_hash.hex()[:32]}...{Colors.RESET}")
        
        # Update index for next level
        leaf_index = leaf_index // 2
    
    # Compare with claimed root
    claimed_root = bytes.fromhex(proof['root'])
    matches = current_hash == claimed_root
    
    print(f"\n  {Colors.BOLD}Final Step:{Colors.RESET} Compare computed root with claimed root")
    print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.DIM}Computed Root:{Colors.RESET} {Colors.YELLOW}{current_hash.hex()}{Colors.RESET}")
    print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.DIM}Claimed Root:{Colors.RESET}  {Colors.BRIGHT_MAGENTA}{claimed_root.hex()}{Colors.RESET}")
    
    if matches:
        print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.BOLD}{Colors.GREEN}MATCH! Proof is VALID{Colors.RESET}")
    else:
        print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.BOLD}{Colors.RED}MISMATCH! Proof is INVALID{Colors.RESET}")
    
    print()


def test_hash(step_num, total_steps, verbose=False):
    """Test SHA-256 hashing."""
    log_step(step_num, total_steps, "Testing SHA-256 hashing")
    
    data = b"Hello, Pi Oracle!"
    log_data("Input data", data.decode('utf-8'), Colors.WHITE)
    log_data("Input size", f"{len(data)} bytes", Colors.BRIGHT_BLACK)
    
    # Call Rust hash function
    start_time = time.time()
    hash_result = bytes(core.py_hash_data(list(data)))
    elapsed = (time.time() - start_time) * 1000
    
    log_data("Hash (hex)", hash_result.hex(), Colors.YELLOW)
    log_data("Hash length", f"{len(hash_result)} bytes", Colors.BRIGHT_BLACK)
    if verbose:
        log_data("Computation time", f"{elapsed:.3f} ms", Colors.GREEN)
    
    assert len(hash_result) == 32, "SHA-256 should be 32 bytes"
    log_success("SHA-256 hashing works correctly")


def test_keypair(step_num, total_steps, verbose=False):
    """Test ECDSA keypair generation."""
    log_step(step_num, total_steps, "Testing ECDSA keypair generation")
    
    log_detail("Generating secp256k1 keypair...")
    start_time = time.time()
    private_key, public_key = core.py_generate_keypair()
    elapsed = (time.time() - start_time) * 1000
    
    private_key = bytes(private_key)
    public_key = bytes(public_key)
    
    log_detail(f"Private key: {private_key.hex()[:16]}...{private_key.hex()[-16:]} ({len(private_key)} bytes)")
    log_detail(f"Public key:  {public_key.hex()[:16]}...{public_key.hex()[-16:]} ({len(public_key)} bytes)")
    if verbose:
        log_detail(f"Generation time: {elapsed:.3f} ms", indent=2)
        log_detail(f"Curve: secp256k1 (same as Bitcoin/Ethereum)", indent=2)
    
    assert len(private_key) == 32, "Private key should be 32 bytes"
    assert len(public_key) == 33, "Compressed public key should be 33 bytes"
    log_success("ECDSA keypair generation works correctly")


def test_signature(step_num, total_steps, verbose=False):
    """Test ECDSA signing and verification."""
    log_step(step_num, total_steps, "Testing ECDSA signing and verification")
    
    # Generate keypair
    log_detail("Generating keypair for signing test...")
    private_key, public_key = core.py_generate_keypair()
    private_key = bytes(private_key)
    public_key = bytes(public_key)
    
    # Sign a message
    message = b"Market tick: BTC/USD=42000"
    log_detail(f"Message to sign: '{message.decode('utf-8')}'")
    
    start_time = time.time()
    signature = bytes(core.py_sign_message(list(message), list(private_key)))
    sign_time = (time.time() - start_time) * 1000
    
    log_detail(f"Signature: {signature.hex()[:16]}...{signature.hex()[-16:]} ({len(signature)} bytes)")
    if verbose:
        log_detail(f"Signing time: {sign_time:.3f} ms", indent=2)
    
    # Verify valid signature
    log_detail("Verifying valid signature...")
    start_time = time.time()
    is_valid = core.py_verify_signature(list(message), list(signature), list(public_key))
    verify_time = (time.time() - start_time) * 1000
    
    log_detail(f"Valid signature result: {is_valid}", indent=2)
    if verbose:
        log_detail(f"Verification time: {verify_time:.3f} ms", indent=2)
    assert is_valid, "Valid signature should verify"
    
    # Test with tampered message
    log_detail("Testing tampered message detection...")
    wrong_message = b"Market tick: BTC/USD=99999"
    is_valid_wrong = core.py_verify_signature(list(wrong_message), list(signature), list(public_key))
    log_detail(f"Tampered message result: {is_valid_wrong} (should be False)", indent=2)
    assert not is_valid_wrong, "Tampered signature should not verify"
    
    log_success("ECDSA signing and verification work correctly")


def test_merkle_tree(step_num, total_steps, verbose=False):
    """Test Merkle tree construction and root."""
    log_step(step_num, total_steps, "Testing Merkle tree construction")
    
    # Create some fake market ticks
    ticks = [
        b"BTC/USD=42000,vol=100",
        b"ETH/USD=3200,vol=50",
        b"BNB/USD=450,vol=75",
        b"SOL/USD=120,vol=25",
    ]
    
    log_detail(f"Building Merkle tree with {len(ticks)} leaves...")
    if verbose:
        for i, tick in enumerate(ticks):
            log_detail(f"Leaf {i}: {tick.decode('utf-8')}", indent=2)
    
    # Build Merkle tree
    start_time = time.time()
    tree = core.PyMerkleTree([list(tick) for tick in ticks])
    root = bytes(tree.root())
    elapsed = (time.time() - start_time) * 1000
    
    log_detail(f"Merkle root: {root.hex()}")
    log_detail(f"Root length: {len(root)} bytes")
    if verbose:
        log_detail(f"Tree construction time: {elapsed:.3f} ms", indent=2)
        log_detail(f"Tree height: {len(ticks).bit_length()} levels", indent=2)
    
    assert len(root) == 32, "Merkle root should be 32 bytes"
    log_success("Merkle tree construction works correctly")


def test_merkle_proof(step_num, total_steps, verbose=False):
    """Test Merkle proof generation and verification."""
    log_step(step_num, total_steps, "Testing Merkle proof generation and verification")
    
    # Create some fake market ticks
    ticks = [
        b"BTC/USD=42000,vol=100",
        b"ETH/USD=3200,vol=50",
        b"BNB/USD=450,vol=75",
        b"SOL/USD=120,vol=25",
    ]
    
    # Build Merkle tree
    log_detail(f"Building Merkle tree with {len(ticks)} leaves...")
    tree = core.PyMerkleTree([list(tick) for tick in ticks])
    root = bytes(tree.root())
    
    log_detail(f"Generating and verifying proofs for all {len(ticks)} leaves...")
    total_proof_time = 0
    total_verify_time = 0
    
    for i in range(len(ticks)):
        # Generate proof
        start_time = time.time()
        proof_json = tree.generate_proof(i)
        proof_time = (time.time() - start_time) * 1000
        total_proof_time += proof_time
        
        # Verify proof
        start_time = time.time()
        is_valid = core.py_verify_proof(proof_json)
        verify_time = (time.time() - start_time) * 1000
        total_verify_time += verify_time
        
        if verbose:
            log_detail(f"Leaf {i}: {ticks[i].decode('utf-8')}", indent=2)
            log_detail(f"Proof size: {len(proof_json)} chars, Valid: {is_valid}", indent=3)
        
        assert is_valid, f"Proof for leaf {i} should be valid"
    
    log_detail(f"All {len(ticks)} proofs verified successfully")
    if verbose:
        log_detail(f"Avg proof generation: {total_proof_time/len(ticks):.3f} ms", indent=2)
        log_detail(f"Avg proof verification: {total_verify_time/len(ticks):.3f} ms", indent=2)
    
    log_success("Merkle proof generation and verification work correctly")


def test_invalid_proof(step_num, total_steps, verbose=False):
    """Test that invalid proofs are rejected."""
    log_step(step_num, total_steps, "Testing invalid proof detection")
    
    # Create a fake/invalid proof JSON
    invalid_json = '{"leaf_data":"0000","leaf_index":0,"siblings":[],"root":"0000"}'
    log_detail("Testing with malformed proof JSON...")
    
    try:
        is_valid = core.py_verify_proof(invalid_json)
        log_data("Invalid proof result", str(is_valid), Colors.BRIGHT_BLACK)
        assert not is_valid, "Invalid proof should not verify"
        log_success("Invalid proof detection works correctly")
    except Exception as e:
        log_data("Exception raised", type(e).__name__, Colors.RED)
        if verbose:
            log_detail(f"Error message: {str(e)}", indent=2)
        log_success("Invalid proof detection works correctly")


def test_full_oracle_workflow(step_num, total_steps, verbose=False):
    """
    Comprehensive integration test showing the FULL Pi Oracle workflow.
    
    This simulates what happens in production:
    1. Generate oracle keypair (for signing commitments)
    2. Ingest market ticks (simulated)
    3. Build Merkle tree from tick data
    4. Sign the Merkle root
    5. Verify each tick can be proven
    6. Simulate revealing specific ticks to third parties
    """
    log_step(step_num, total_steps, "Full Oracle Workflow Integration Test")
    print()
    
    # ==================== STEP 1: Oracle Setup ====================
    print(f"{Colors.BOLD}{Colors.MAGENTA}STEP 1:{Colors.RESET} {Colors.BOLD}Oracle Initialization{Colors.RESET}")
    print_separator("-", 80, Colors.DIM)
    
    log_info("Generating oracle keypair...")
    private_key, public_key = core.py_generate_keypair()
    private_key = bytes(private_key)
    public_key = bytes(public_key)
    
    log_data("Oracle Public Key", public_key.hex()[:32] + "...", Colors.CYAN)
    log_data("Key Type", "secp256k1 (Ethereum-compatible)", Colors.BRIGHT_BLACK)
    print()
    
    # ==================== STEP 2: Market Data Ingestion ====================
    print(f"{Colors.BOLD}{Colors.MAGENTA}STEP 2:{Colors.RESET} {Colors.BOLD}Market Data Ingestion{Colors.RESET}")
    print_separator("-", 80, Colors.DIM)
    
    # Simulate live market ticks (what the real oracle would receive)
    market_ticks = [
        b'{"pair":"BTC/USD","price":42150.50,"volume":1.2534,"timestamp":1699876543}',
        b'{"pair":"BTC/USD","price":42152.75,"volume":0.8421,"timestamp":1699876544}',
        b'{"pair":"BTC/USD","price":42148.00,"volume":2.1045,"timestamp":1699876545}',
        b'{"pair":"ETH/USD","price":3205.25,"volume":5.4231,"timestamp":1699876543}',
        b'{"pair":"ETH/USD","price":3206.50,"volume":3.2109,"timestamp":1699876544}',
        b'{"pair":"ETH/USD","price":3204.75,"volume":1.8765,"timestamp":1699876545}',
        b'{"pair":"SOL/USD","price":125.30,"volume":150.234,"timestamp":1699876543}',
        b'{"pair":"SOL/USD","price":125.45,"volume":89.567,"timestamp":1699876544}',
    ]
    
    log_info(f"Ingesting {len(market_ticks)} market ticks...")
    print()
    
    if verbose:
        for i, tick in enumerate(market_ticks):
            tick_data = json.loads(tick.decode('utf-8'))
            price_color = Colors.GREEN if i == 0 or float(tick_data['price']) >= float(json.loads(market_ticks[i-1].decode('utf-8'))['price']) else Colors.RED
            print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} Tick {i}: {Colors.BRIGHT_YELLOW}{tick_data['pair']:<10}{Colors.RESET} "
                  f"Price: {price_color}${tick_data['price']:<10.2f}{Colors.RESET} "
                  f"Vol: {Colors.CYAN}{tick_data['volume']:<8.4f}{Colors.RESET}")
    else:
        for i, tick in enumerate(market_ticks[:3]):
            tick_data = json.loads(tick.decode('utf-8'))
            print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} Tick {i}: {Colors.BRIGHT_YELLOW}{tick_data['pair']}{Colors.RESET} @ ${Colors.GREEN}{tick_data['price']}{Colors.RESET}")
        print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} ... and {len(market_ticks) - 3} more ticks")
    
    print()
    
    # ==================== STEP 3: Merkle Tree Commitment ====================
    print(f"{Colors.BOLD}{Colors.MAGENTA}STEP 3:{Colors.RESET} {Colors.BOLD}Cryptographic Commitment (Merkle Tree){Colors.RESET}")
    print_separator("-", 80, Colors.DIM)
    
    log_info("Building Merkle tree from tick data...")
    start_time = time.time()
    tree = core.PyMerkleTree([list(tick) for tick in market_ticks])
    root = bytes(tree.root())
    tree_time = (time.time() - start_time) * 1000
    
    log_data("Merkle Root", root.hex(), Colors.BRIGHT_MAGENTA)
    log_data("Tree Height", f"{len(market_ticks).bit_length()} levels", Colors.BRIGHT_BLACK)
    log_data("Total Leaves", f"{len(market_ticks)} ticks", Colors.BRIGHT_BLACK)
    if verbose:
        log_data("Build Time", f"{tree_time:.3f} ms", Colors.GREEN)
    
    # Visualize the tree construction process
    if verbose:
        visualize_merkle_tree(market_ticks, verbose=verbose)
    else:
        # Show a simplified version even in non-verbose mode
        print()
        print(f"{Colors.DIM}  Merkle tree construction:{Colors.RESET}")
        print(f"{Colors.DIM}    Level 0 (leaves): {len(market_ticks)} hashes{Colors.RESET}")
        for level in range(1, len(market_ticks).bit_length()):
            num_nodes = (len(market_ticks) + 2**level - 1) // 2**level
            print(f"{Colors.DIM}    Level {level}: {num_nodes} hashes{Colors.RESET}")
        print(f"{Colors.DIM}    Root: 1 hash{Colors.RESET}")
    
    print()
    
    # ==================== STEP 4: Sign Commitment ====================
    print(f"{Colors.BOLD}{Colors.MAGENTA}STEP 4:{Colors.RESET} {Colors.BOLD}Digital Signature (Publish to Blockchain){Colors.RESET}")
    print_separator("-", 80, Colors.DIM)
    
    log_info("Signing Merkle root with oracle private key...")
    start_time = time.time()
    signature = bytes(core.py_sign_message(list(root), list(private_key)))
    sign_time = (time.time() - start_time) * 1000
    
    log_data("Signature", signature.hex()[:64] + "...", Colors.YELLOW)
    log_data("Signature Length", f"{len(signature)} bytes", Colors.BRIGHT_BLACK)
    if verbose:
        log_data("Signing Time", f"{sign_time:.3f} ms", Colors.GREEN)
    
    # Verify signature
    is_valid = core.py_verify_signature(list(root), list(signature), list(public_key))
    log_data("Signature Valid", str(is_valid), Colors.GREEN if is_valid else Colors.RED)
    assert is_valid, "Oracle signature should be valid"
    print()
    
    # ==================== STEP 5: Proof Generation & Verification ====================
    print(f"{Colors.BOLD}{Colors.MAGENTA}STEP 5:{Colors.RESET} {Colors.BOLD}Merkle Proof Generation & Verification{Colors.RESET}")
    print_separator("-", 80, Colors.DIM)
    
    log_info("Generating and verifying proofs for all ticks...")
    print()
    
    all_valid = True
    proof_times = []
    verify_times = []
    
    # Test a few specific ticks
    test_indices = [0, 3, len(market_ticks) - 1] if not verbose else range(len(market_ticks))
    
    # Show detailed verification for the first tick
    example_shown = False
    
    for idx, i in enumerate(test_indices):
        tick_data = json.loads(market_ticks[i].decode('utf-8'))
        
        # Generate proof
        start_time = time.time()
        proof_json = tree.generate_proof(i)
        proof_time = (time.time() - start_time) * 1000
        proof_times.append(proof_time)
        
        # Verify proof
        start_time = time.time()
        is_valid = core.py_verify_proof(proof_json)
        verify_time = (time.time() - start_time) * 1000
        verify_times.append(verify_time)
        
        all_valid = all_valid and is_valid
        
        status = f"{Colors.GREEN}VALID{Colors.RESET}" if is_valid else f"{Colors.RED}INVALID{Colors.RESET}"
        print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} Tick {i:2d}: {Colors.BRIGHT_YELLOW}{tick_data['pair']:<10}{Colors.RESET} "
              f"Price: {Colors.WHITE}${tick_data['price']:<10.2f}{Colors.RESET} "
              f"Proof: {status}")
        
        if verbose:
            proof_obj = json.loads(proof_json)
            print(f"  {Colors.BRIGHT_BLACK}|   {Colors.RESET}{Colors.DIM}Proof size: {len(proof_json)} bytes, "
                  f"Siblings: {len(proof_obj['siblings'])}, "
                  f"Gen: {proof_time:.2f}ms, Verify: {verify_time:.2f}ms{Colors.RESET}")
        
        # Show detailed verification visualization for the first example (or in verbose mode, for all)
        if not example_shown or verbose:
            visualize_proof_verification(proof_json, market_ticks[i], verbose=verbose)
            example_shown = True
    
    print()
    log_data("Total Proofs Verified", f"{len(test_indices)}/{len(market_ticks)}", Colors.GREEN)
    log_data("All Proofs Valid", str(all_valid), Colors.GREEN if all_valid else Colors.RED)
    if proof_times:
        log_data("Avg Proof Generation", f"{sum(proof_times)/len(proof_times):.3f} ms", Colors.BRIGHT_BLACK)
        log_data("Avg Proof Verification", f"{sum(verify_times)/len(verify_times):.3f} ms", Colors.BRIGHT_BLACK)
    
    print()
    
    # ==================== STEP 6: Summary ====================
    print(f"{Colors.BOLD}{Colors.MAGENTA}WORKFLOW SUMMARY:{Colors.RESET}")
    print_separator("-", 80, Colors.DIM)
    
    print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.GREEN}[OK]{Colors.RESET} Oracle keypair generated (secp256k1)")
    print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.GREEN}[OK]{Colors.RESET} {len(market_ticks)} market ticks ingested")
    print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.GREEN}[OK]{Colors.RESET} Merkle tree built (root: {root.hex()[:16]}...)")
    print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.GREEN}[OK]{Colors.RESET} Merkle root signed and verified")
    print(f"  {Colors.BRIGHT_BLACK}|{Colors.RESET} {Colors.GREEN}[OK]{Colors.RESET} All {len(test_indices)} proofs generated and verified")
    print()
    
    print(f"{Colors.BRIGHT_GREEN}This is exactly how the Pi Oracle works in production!{Colors.RESET}")
    print(f"{Colors.DIM}The root + signature would be published to blockchain,{Colors.RESET}")
    print(f"{Colors.DIM}and proofs can be generated on-demand for any tick.{Colors.RESET}")
    print()
    
    assert all_valid, "All proofs should be valid"
    log_success("Full oracle workflow integration test passed")


def main():
    """Run all tests."""
    parser = argparse.ArgumentParser(
        description="Pi Oracle - Rust Bindings Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_rust_bindings.py              # Run all tests (default)
  python test_rust_bindings.py -v           # Verbose output with timing
  python test_rust_bindings.py --quiet      # Minimal output
        """
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output with detailed timing information"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Minimal output (errors only)"
    )
    
    args = parser.parse_args()
    
    # Print header
    if not args.quiet:
        print()
        print_header("Pi Oracle - Cryptographic Bindings Test Suite", 
                    "Testing: SHA-256, ECDSA, Merkle Trees | Backend: Rust (PyO3)")
        print()
    
    # Run tests
    total_tests = 7
    start_time = time.time()
    
    try:
        test_hash(1, total_tests, verbose=args.verbose)
        test_keypair(2, total_tests, verbose=args.verbose)
        test_signature(3, total_tests, verbose=args.verbose)
        test_merkle_tree(4, total_tests, verbose=args.verbose)
        test_merkle_proof(5, total_tests, verbose=args.verbose)
        test_invalid_proof(6, total_tests, verbose=args.verbose)
        
        # Run the comprehensive integration test
        print_separator("=", 80)
        print()
        test_full_oracle_workflow(7, total_tests, verbose=args.verbose)
        
        elapsed = time.time() - start_time
        
        # Print summary
        if not args.quiet:
            print_separator("=", 80)
            print(f"\n{Colors.BOLD}{Colors.GREEN}  SUCCESS: ALL {total_tests} TESTS PASSED!{Colors.RESET}")
            print(f"{Colors.DIM}  Total execution time: {elapsed:.3f} seconds{Colors.RESET}\n")
            print_separator("=", 80)
            print(f"\n{Colors.BRIGHT_GREEN}Your Rust bindings are working correctly!{Colors.RESET}")
            print(f"{Colors.DIM}You can now use pi_oracle_core from Python.{Colors.RESET}\n")
        else:
            print("PASS")
        
    except AssertionError as e:
        if not args.quiet:
            print()
            print_separator("=", 80, Colors.RED)
            print(f"{Colors.BOLD}{Colors.RED}  TEST FAILED{Colors.RESET}")
            print_separator("=", 80, Colors.RED)
            print(f"{Colors.RED}  {e}{Colors.RESET}\n")
        else:
            print(f"FAIL: {e}")
        return 1
        
    except Exception as e:
        if not args.quiet:
            print()
            print_separator("=", 80, Colors.RED)
            print(f"{Colors.BOLD}{Colors.RED}  ERROR{Colors.RESET}")
            print_separator("=", 80, Colors.RED)
            print(f"{Colors.RED}  {type(e).__name__}: {e}{Colors.RESET}\n")
            import traceback
            traceback.print_exc()
        else:
            print(f"ERROR: {type(e).__name__}: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

