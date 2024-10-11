use crate::utils::scalar_from_hex::scalar_from_hex;
use crate::utils::serialize_point::{deserialize_point, serialize_point};
use crate::utils::serialize_ring::{deserialize_ring, serialize_ring};
use crate::utils::sha256::sha_256;
use crate::utils::{hash_to_secp256k1::hash_to_secp256k1, hex_to_decimal::hex_to_decimal};
use base64::engine::general_purpose;
use base64::Engine;
use core::str;
use ethabi::ethereum_types::U256;
use ethabi::{encode, Token};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{AffinePoint, Scalar};
use serde::Deserialize;
use sha2::{Digest, Sha256};

// Define a struct that matches the structure of your JSON string
#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct StringifiedLsag {
    pub message: String,
    pub ring: Vec<String>,
    pub c: String,
    pub responses: Vec<String>,
    pub keyImage: String,
    pub linkabilityFlag: String,
}
/// Parameters required for the compute_c function
pub struct Params {
    pub index: usize,
    pub previous_r: Scalar,
    pub previous_c: Scalar,
    pub previous_index: usize,
    pub linkability_flag: Option<String>,
    pub key_image: AffinePoint,
}
#[derive(Debug)]
pub struct MinimalLsag {
    pub message: String,
    pub key_image: AffinePoint,
    pub linkability_flag: Option<String>,
    pub ring: Vec<AffinePoint>,
}
/// Computes the 'cee' value based on the provided parameters
pub fn compute_c(
    ring: &[AffinePoint], // todo: ensure ring is sorted
    serialized_ring: String,
    message_digest: String,
    params: &Params,
    // curve_order: Scalar,
) -> Scalar {
    let g = AffinePoint::GENERATOR;

    let point =
        ((g * params.previous_r) + (ring[params.previous_index] * params.previous_c)).to_affine();

    let mapped = hash_to_secp256k1(
        serialize_point(ring[params.previous_index])
            + &params.linkability_flag.clone().unwrap_or("".to_string()),
    );

    let hash_content = "".to_string()
        + &serialized_ring
        + &hex_to_decimal(&message_digest).unwrap()
        + &serialize_point(point)
        + &serialize_point(
            ((mapped * params.previous_r) + (params.key_image * params.previous_c)).to_affine(),
        );

    let hash = sha_256(&[hash_content]);

    scalar_from_hex(&hash).unwrap() // todo: compute mod order: % curve_order;
}

// Function to convert a JSON string into a Rust struct
fn convert_string_to_json(json_str: &str) -> StringifiedLsag {
    // Deserialize the JSON string into the Rust struct
    serde_json::from_str(json_str).unwrap()
}

/// Verify a base64 encoded LSAG signature.
/// Converts a base64 encoded LSAG signature and verifies it.
pub fn verify_b64_lsag(b64_signature: String) -> Option<[u8; 32]> {
    // Decode the base64 string
    let decoded_bytes = general_purpose::STANDARD
        .decode(b64_signature.as_bytes())
        .unwrap();

    // Convert the byte array to utf8 string
    let decoded_string = match str::from_utf8(&decoded_bytes) {
        Ok(ascii) => ascii,
        Err(_) => panic!("Failed to convert decoded bytes to ASCII string"),
    };

    // Convert the string to json
    let json = convert_string_to_json(decoded_string); // Assume the conversion returns a Result
    let ring_points = match deserialize_ring(&json.ring) {
        Ok(points) => points,
        Err(e) => {
            println!("Error deserializing ring: {}", e);
            return None; // Return false if deserialization fails
        }
    };

    let key_image = match deserialize_point(json.keyImage.clone()) {
        Ok(point) => point,
        Err(e) => {
            println!("Error deserializing keyImage: {}", e);
            return None; // Return false if deserialization fails
        }
    };

    let responses: Vec<Scalar> = json
        .responses
        .iter()
        .map(|response| match scalar_from_hex(response) {
            Ok(scalar) => scalar,
            Err(e) => {
                eprintln!("Error parsing scalar from hex '{}': {}", response, e);
                panic!("Failed to parse scalar");
            }
        })
        .collect();

    let is_valid = verify_lsag(
        &ring_points,
        json.message.clone(),
        scalar_from_hex(&json.c).ok()?,
        &responses,
        key_image,
        Some(json.linkabilityFlag.clone()),
    );

    if is_valid {
        let hash = to_minimal_lsag_digest(
            &ring_points,
            json.message.clone(),
            key_image,
            Some(json.linkabilityFlag.clone()),
        );
        Some(hash)
    } else {
        None // Return None if the signature is invalid
    }
}

/// Verifies a ring signature.
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify_lsag(
    ring: &[AffinePoint],
    message: String,
    c0: Scalar,
    responses: &[Scalar],
    key_image: AffinePoint,
    linkability_flag: Option<String>,
) -> bool {
    // // Check that all points in the ring are valid
    // for point in ring {
    //     if !check_low_order(point) { // todo: add the check_low_order function
    //         panic!("The public key {:?} is not valid", point);
    //     }
    // }

    // Ensure that the ring and responses have matching lengths
    if ring.len() != responses.len() {
        panic!("Ring and responses must have the same length");
    }
    let message_digest = sha_256(&[message]);

    let serialized_ring = serialize_ring(ring);

    // Initialize lastComputedCp with c0
    let mut last_computed_c = c0;

    // Compute the c values: c1', c2', ..., cn', c0'
    for i in responses.iter().enumerate().take(ring.len()) {
        let params = Params {
            index: (i.0 + 1) % ring.len(),
            previous_r: responses[i.0],
            previous_c: last_computed_c,
            previous_index: i.0,
            key_image,
            linkability_flag: linkability_flag.clone(),
        };

        let c = compute_c(
            ring,
            serialized_ring.clone(),
            message_digest.clone(),
            &params,
        );

        last_computed_c = c;
    }

    // Return true if c0 == c0'
    c0 == last_computed_c
}

pub fn to_minimal_lsag_digest(
    ring: &[AffinePoint],
    message: String,
    key_image: AffinePoint,
    linkability_flag: Option<String>,
) -> [u8; 32] {
    let mini_lsag = MinimalLsag {
        message: message.clone(),
        linkability_flag: linkability_flag.clone(),
        key_image,
        ring: ring.to_vec(),
    };
    let encoded = abi_encode_minimal_lsag(&mini_lsag);
    let mut result = vec![0u8; 32];
    result[31] = 32u8;
    result.extend_from_slice(&encoded);
    //here result is the same as the abi.encode in solidity
    let hex_string = format!("{}", hex::encode(&result));
    dbg!(&hex_string);
    //the issue come from the result of the sha256 function here.:qa

    let mut hasher = Sha256::new();
    hasher.update(&hex::decode(hex_string).expect("Error while decoding hex value"));
    let hash_result = hasher.finalize();
    let hash_bytes32: [u8; 32] = hash_result.into();
    dbg!(hex::encode(hash_bytes32));
    hash_result.into()
}

fn abi_encode_minimal_lsag(lsag: &MinimalLsag) -> Vec<u8> {
    dbg!(lsag);
    let tokens = vec![
        Token::String(lsag.message.clone()),
        Token::String(lsag.linkability_flag.clone().unwrap_or_default()),
        Token::Uint(affine_point_to_uint256(&lsag.key_image)), // Encode key_image as a uint256
        Token::Array(
            lsag.ring
                .iter()
                .map(|point| Token::Uint(affine_point_to_uint256(&point))) // Each point encoded as uint256
                .collect(),
        ),
    ];
    encode(&tokens)
}

fn affine_point_to_uint256(point: &AffinePoint) -> U256 {
    // Assuming `point.x()` returns a `[u8; 32]` representing the x-coordinate
    let x_bytes = point.x().to_vec(); // Get x as [u8; 32]
    dbg!(U256::from_big_endian(&x_bytes));
    U256::from_big_endian(&x_bytes) // Convert the byte array to U256
}
