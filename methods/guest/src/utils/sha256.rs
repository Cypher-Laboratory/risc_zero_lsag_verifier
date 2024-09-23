use hex;
use sha2::{Digest, Sha256};

/// SHA256 function
/// concatenates the input strings and returns the Keccak256 hash as a hexadecimal string
pub fn sha_256(input: &[String]) -> String {
    // Convert each element to a string and concatenate them
    let serialized: String = input.iter().map(|x| x.to_string()).collect();

    // Create a Keccak256 hasher instance
    let mut hasher = Sha256::new();

    // Update the hasher with the serialized input
    hasher.update(serialized.as_bytes());

    // Retrieve the hash result
    let result = hasher.finalize();

    // Convert the hash result to a hexadecimal string
    hex::encode(result)
}

// example of using sha256
// let input = ["0x1".to_string(), "0x2".to_string(), "0x3".to_string()];

// // Create a sha256 hasher instance
// let hashed = utils::sha256::sha_256(input.as_ref());

// println!("Input: {}", input.iter().map(|x| x.to_string()).collect::<String>());
// println!("SHA256 Hash: {}", hashed);
