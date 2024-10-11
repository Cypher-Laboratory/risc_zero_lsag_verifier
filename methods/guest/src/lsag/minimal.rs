use ethabi::ethereum_types::U256;
use ethabi::{encode, Token};
use k256::{elliptic_curve::point::AffineCoordinates, AffinePoint};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct MinimalLsag {
    pub message: String,
    pub key_image: AffinePoint,
    pub linkability_flag: Option<String>,
    pub ring: Vec<AffinePoint>,
}

pub fn to_minimal_lsag_digest(
    ring: &[AffinePoint],
    message: String,
    key_image: AffinePoint,
    linkability_flag: Option<String>,
) -> [u8; 32] {
    let mini_lsag = MinimalLsag {
        message,
        linkability_flag,
        key_image,
        ring: ring.to_vec(),
    };
    let encoded = abi_encode_minimal_lsag(&mini_lsag);

    let mut hasher = Sha256::new();
    hasher.update(encoded);
    hasher.finalize().into()
}

fn abi_encode_minimal_lsag(lsag: &MinimalLsag) -> Vec<u8> {
    let tokens = vec![
        Token::String(lsag.message.clone()),
        Token::String(lsag.linkability_flag.clone().unwrap_or_default()),
        Token::Uint(affine_point_to_uint256(&lsag.key_image)),
        Token::Array(
            lsag.ring
                .iter()
                .map(|point| Token::Uint(affine_point_to_uint256(&point)))
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
