use crate::utils::{hash_to_secp256k1, hex_to_decimal, scalar_from_hex, serialize_point, sha_256};
use k256::{AffinePoint, Scalar};

pub struct Params<'a> {
    pub index: usize,
    pub previous_r: Scalar,
    pub previous_c: Scalar,
    pub previous_index: usize,
    pub key_image: AffinePoint,
    pub linkability_flag: Option<&'a String>,
}

pub fn compute_c<'a>(
    ring: &[AffinePoint],
    serialized_ring: &String,
    message_digest: &String,
    params: &Params<'a>,
) -> Scalar {
    let g = AffinePoint::GENERATOR;

    let point =
        ((g * params.previous_r) + (ring[params.previous_index] * params.previous_c)).to_affine();

    // Borrowing linkability_flag without cloning
    let mapped = hash_to_secp256k1(
        serialize_point(ring[params.previous_index])
            + params.linkability_flag.map(|s| s.as_str()).unwrap_or(""),
    );

    let hash_content = format!(
        "{}{}{}{}",
        serialized_ring,
        hex_to_decimal(&message_digest).unwrap(),
        serialize_point(point),
        serialize_point(
            ((mapped * params.previous_r) + (params.key_image * params.previous_c)).to_affine()
        )
    );

    let hash = sha_256(&[&hash_content]);
    scalar_from_hex(&hash).unwrap()
}
