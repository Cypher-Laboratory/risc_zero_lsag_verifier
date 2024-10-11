use crate::lsag::compute::{compute_c, Params};
use crate::lsag::conversion::convert_string_to_json;
use crate::lsag::minimal::to_minimal_lsag_digest;
use crate::utils::{deserialize_point, deserialize_ring, scalar_from_hex, serialize_ring, sha_256};

use base64::engine::general_purpose;
use base64::Engine;
use core::str;
use k256::{AffinePoint, Scalar};

/// Verifies a base64-encoded LSAG (Linkable Spontaneous Anonymous Group) signature.
///
/// This function decodes the base64 string, parses the resulting JSON, and verifies the ring signature.
///
/// # Arguments
/// * `b64_signature` - A base64-encoded LSAG signature.
///
/// # Returns
/// * `Some([u8; 32])` - Returns a 32-byte hash if the signature is valid.
/// * `None` - Returns `None` if the signature verification fails.
///
/// # Panics
/// This function will panic if the base64 decoding or JSON parsing fails.
pub fn verify_b64_lsag(b64_signature: String) -> Option<[u8; 32]> {
    let decoded_bytes = general_purpose::STANDARD
        .decode(b64_signature.as_bytes())
        .ok()?;
    let decoded_string = str::from_utf8(&decoded_bytes).ok()?;

    let json = match convert_string_to_json(decoded_string) {
        Ok(json) => json,
        Err(_) => return None,
    };
    let ring_points = deserialize_ring(&json.ring).ok()?;
    let key_image = deserialize_point(json.keyImage).ok()?;

    let responses: Vec<Scalar> = json
        .responses
        .iter()
        .filter_map(|response| scalar_from_hex(response).ok())
        .collect();

    let is_valid = verify_lsag(
        &ring_points,
        &json.message,
        scalar_from_hex(&json.c).ok()?,
        &responses,
        key_image,
        Some(&json.linkabilityFlag),
    );

    if is_valid {
        let hash = to_minimal_lsag_digest(
            &ring_points,
            &json.message,
            key_image,
            Some(json.linkabilityFlag).as_deref(),
        );
        Some(hash)
    } else {
        None
    }
}
/// Verifies a ring signature (LSAG).
///
/// # Arguments
/// * `ring` - A list of public keys (ring) used in the signature.
/// * `message` - The message that was signed.
/// * `c0` - The initial scalar value (challenge).
/// * `responses` - The response scalars for each ring member.
/// * `key_image` - The key image used in the signature.
/// * `linkability_flag` - Optional flag for linkability.
///
/// # Returns
/// * `true` if the signature is valid, `false` otherwise.
pub fn verify_lsag(
    ring: &[AffinePoint],
    message: &str,
    c0: Scalar,
    responses: &[Scalar],
    key_image: AffinePoint,
    linkability_flag: Option<&str>,
) -> bool {
    if ring.len() != responses.len() {
        return false;
    }

    let message_digest = sha_256(&[message]);
    let serialized_ring = serialize_ring(ring);
    let mut last_computed_c = c0;

    for (i, response) in responses.iter().enumerate() {
        let params = Params {
            index: (i + 1) % ring.len(),
            previous_r: *response,
            previous_c: last_computed_c,
            previous_index: i,
            key_image,
            linkability_flag,
        };
        match compute_c(ring, &serialized_ring, &message_digest, &params) {
            Ok(computed_c) => last_computed_c = computed_c,
            Err(_) => return false, // Return false if compute_c returns an error
        };
    }

    c0 == last_computed_c
}
