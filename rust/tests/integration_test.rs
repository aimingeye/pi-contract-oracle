// Integration tests - test the library from outside
// These go in tests/ directory (separate from src/)

use pi_oracle_core::hash_data;

#[test]
fn test_hash_known_value() {
    // Test against known SHA-256 hash
    let data = b"hello world";
    let hash = hash_data(data);
    
    // Known SHA-256 of "hello world"
    let expected = hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").unwrap();
    
    assert_eq!(hash, expected);
}

