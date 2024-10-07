use core::str;
use ethabi::{encode, Token};
use k256::elliptic_curve::point::AffineCoordinates;
use sha2::{Digest, Sha256};

use crate::utils::scalar_from_hex::scalar_from_hex;
use crate::utils::serialize_point::{deserialize_point, serialize_point};
use crate::utils::serialize_ring::{deserialize_ring, serialize_ring};
use crate::utils::sha256::sha_256;
use crate::utils::{hash_to_secp256k1::hash_to_secp256k1, hex_to_decimal::hex_to_decimal};
use base64::engine::general_purpose;
use base64::Engine;
use k256::{AffinePoint, Scalar};
use serde::Deserialize;

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
    let mut hasher = Sha256::new();
    hasher.update(&encoded);
    let result = hasher.finalize();
    result.into()
}

fn abi_encode_minimal_lsag(lsag: &MinimalLsag) -> Vec<u8> {
    let tokens = vec![
        Token::String(lsag.message.clone()),
        Token::String(lsag.linkability_flag.clone().unwrap_or_default()),
        Token::FixedBytes(affine_point_to_bytes(&lsag.key_image)),
        Token::Array(
            lsag.ring
                .iter()
                .map(|point| Token::FixedBytes(affine_point_to_bytes(point)))
                .collect(),
        ),
    ];

    encode(&tokens)
}

fn affine_point_to_bytes(point: &AffinePoint) -> Vec<u8> {
    // Similar to key_image_to_bytes, but for a single point in the ring
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&point.x());
    bytes
}

#[cfg(test)]
mod tests {
    use super::verify_lsag;
    use crate::{
        lsag_verifier::{compute_c, Params},
        utils::{
            scalar_from_hex::scalar_from_hex, scalar_to_string::scalar_to_string,
            test_utils::get_ring,
        },
    };
    use elliptic_curve::{sec1::FromEncodedPoint, PrimeField};
    use k256::{AffinePoint, EncodedPoint, Scalar};

    #[test]
    fn test_compute_c() {
        let ring = get_ring(&[
            (
                "10332262407579932743619774205115914274069865521774281655691935407979316086911",
                "100548694955223641708987702795059132275163693243234524297947705729826773642827",
            ),
            (
                "15164162595175125008547705889856181828932143716710538299042410382956573856362",
                "20165396248642806335661137158563863822683438728408180285542980607824890485122",
            ),
            (
                "23289579613515307249488379845935313471996837170244623503719929765426073488571",
                "51508290999221377635014061085578700551081950582306096405012518980034910355762",
            ),
        ]);

        let key_image = ring[0];

        let params = Params {
            index: 2,
            previous_r: Scalar::from_u128(123),
            previous_c: Scalar::from_u128(456),
            previous_index: 1,
            linkability_flag: Some("string".to_string()),
            key_image,
        };

        let result = compute_c(
            &ring,
            "103322624075799327436197742051159142740698655217742816556919354079793160869111151641625951751250085477058898561818289321437167105382990424103829565738563622232895796135153072494883798459353134719968371702446235037199297654260734885712".to_string(),
            "00000000000000000000000000000000000000000000000000000000075BCD15".to_string(), // hex for "123456789" (padded to 32 bytes)
            &params,
        );
        let expected_result = "9417d5df80043f0a291210af035900c6863a560836fe23b25fc92b46fd87cb16";
        assert_eq!(scalar_to_string(&result), expected_result);
    }

    #[test]
    fn test_verify_lsag() {
        // Define the points as strings
        let points = [
            (
                "4051293998585674784991639592782214972820158391371785981004352359465450369227",
                "88166831356626186178414913298033275054086243781277878360288998796587140930350",
            ),
            (
                "10332262407579932743619774205115914274069865521774281655691935407979316086911",
                "100548694955223641708987702795059132275163693243234524297947705729826773642827",
            ),
            (
                "15164162595175125008547705889856181828932143716710538299042410382956573856362",
                "20165396248642806335661137158563863822683438728408180285542980607824890485122",
            ),
            (
                "23289579613515307249488379845935313471996837170244623503719929765426073488571",
                "51508290999221377635014061085578700551081950582306096405012518980034910355762",
            ),
        ];
        let ring = get_ring(&points);

        let x = scalar_from_hex("191eb9f0636a5b1a87ed66cc00d5b3ffa35d4e04c4b21c8e48db987abb600b11");
        let y = scalar_from_hex("2cdf899ff765f26abb272b8228ccc4b1f69192e614d9c0d44a52b78bb9af8774");
        let key_image = AffinePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(
            &x.unwrap().into(),
            &y.unwrap().into(),
            false,
        ));
        let c: k256::Scalar =
            scalar_from_hex("86379b43861e950b5fa4b7571aff0c6004578e71280aaedb993833c9bde63c43")
                .unwrap();

        let result = verify_lsag(
            &ring,
            "message".to_string(),
            c,
            &[
                scalar_from_hex("d6c1854eeb132d5886ac590c530a55a7fba3d92c4eb6896a728b0a61899ad902")
                    .unwrap(),
                scalar_from_hex("6a51d731b398036ed3b3b5cfd206407a35fd11faa2bbad1658bcf9f08b9c5fb8")
                    .unwrap(),
                scalar_from_hex("6a51d731b398036ed3b3b5cfd206407a35fd11faa2bbad1658bcf9f08b9c5fb8")
                    .unwrap(),
                scalar_from_hex("6a51d731b398036ed3b3b5cfd206407a35fd11faa2bbad1658bcf9f08b9c5fb8")
                    .unwrap(),
            ],
            key_image.unwrap(),
            Some("linkability flag".to_string()),
        );

        assert!(result);
    }
}
