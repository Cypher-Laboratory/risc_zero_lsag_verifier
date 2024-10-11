use crate::utils::{hash_to_secp256k1, hex_to_decimal, scalar_from_hex, serialize_point, sha_256};
use k256::{AffinePoint, Scalar};

pub struct Params<'a> {
    pub index: usize,
    pub previous_r: Scalar,
    pub previous_c: Scalar,
    pub previous_index: usize,
    pub key_image: AffinePoint,
    pub linkability_flag: Option<&'a str>,
}

pub fn compute_c<'a>(
    ring: &[AffinePoint],
    serialized_ring: &str,
    message_digest: &str,
    params: &Params<'a>,
) -> Result<Scalar, String> {
    let g = AffinePoint::GENERATOR;
    let point =
        ((g * params.previous_r) + (ring[params.previous_index] * params.previous_c)).to_affine();

    let serialized_point = serialize_point(ring[params.previous_index])
        .map_err(|e| format!("Failed to serialize point: {}", e))?;

    let serialized_point_and_flag = format!(
        "{}{}",
        serialized_point,
        params.linkability_flag.unwrap_or("")
    );

    let mapped = hash_to_secp256k1(&serialized_point_and_flag)
        .map_err(|_| "Failed to map to secp256k1 point".to_string())?;
    let decimal_digest = hex_to_decimal(message_digest)
        .map_err(|_| "Failed to convert message digest".to_string())?;
    let serialized_computed_point =
        serialize_point(point).map_err(|e| format!("Failed to serialize computed point: {}", e))?;
    let combined_point = (mapped * params.previous_r) + (params.key_image * params.previous_c);
    let serialized_combined_point = serialize_point(combined_point.to_affine())
        .map_err(|e| format!("Failed to serialize combined point: {}", e))?;
    let hash_content = format!(
        "{}{}{}{}",
        serialized_ring, decimal_digest, serialized_computed_point, serialized_combined_point
    );
    let hash = sha_256(&[&hash_content]);
    scalar_from_hex(&hash).map_err(|_| "Failed to convert hash to scalar".to_string())
}
