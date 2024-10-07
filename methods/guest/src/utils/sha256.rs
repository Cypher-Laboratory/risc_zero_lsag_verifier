use hex;
use sha2::{Digest, Sha256};

/// SHA256 function
/// concatenates the input strings and returns the Keccak256 hash as a hexadecimal string
pub fn sha_256(input: &[String]) -> String {
    let serialized: String = input.iter().map(|x| x.to_string()).collect();
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

// example of using sha256
// let input = ["0x1".to_string(), "0x2".to_string(), "0x3".to_string()];

// // Create a sha256 hasher instance
// let hashed = utils::sha256::sha_256(input.as_ref());

// println!("Input: {}", input.iter().map(|x| x.to_string()).collect::<String>());
// println!("SHA256 Hash: {}", hashed);
