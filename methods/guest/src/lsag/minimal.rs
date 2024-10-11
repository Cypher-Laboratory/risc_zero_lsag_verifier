use ethabi::ethereum_types::U256;
use ethabi::{encode, Token};
use k256::{elliptic_curve::point::AffineCoordinates, AffinePoint};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct MinimalLsag<'a> {
    pub message: &'a str,
    pub key_image: AffinePoint,
    pub linkability_flag: Option<&'a str>,
    pub ring: Vec<AffinePoint>,
}

pub fn to_minimal_lsag_digest<'a>(
    ring: &[AffinePoint],
    message: &str,
    key_image: AffinePoint,
    linkability_flag: Option<&'a str>,
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
        Token::String(lsag.message.to_string()), // Use to_string() to convert &str to String
        Token::String(lsag.linkability_flag.unwrap_or_default().to_string()), // Unwrap directly
        Token::Uint(affine_point_to_uint256(&lsag.key_image)),
        Token::Array(
            lsag.ring
                .iter()
                .map(|point| Token::Uint(affine_point_to_uint256(point)))
                .collect(),
        ),
    ];
    encode(&tokens)
}

fn affine_point_to_uint256(point: &AffinePoint) -> U256 {
    // Assuming `point.x()` returns a `[u8; 32]` representing the x-coordinate
    let x_bytes = point.x().to_vec(); // Returns a byte array slice directly
    U256::from_big_endian(&x_bytes) // Use the byte slice without to_vec()
}
