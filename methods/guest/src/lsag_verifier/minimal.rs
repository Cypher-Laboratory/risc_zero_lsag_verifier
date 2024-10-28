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

//TODO use both x and y coordinate
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
    //set the offset
    let mut result = vec![0u8; 32];
    result[31] = 32u8;

    let tokens = vec![
        Token::String(lsag.message.to_string()),
        Token::String(lsag.linkability_flag.unwrap_or_default().to_string()),
        Token::Uint(affine_point_to_uint256(&lsag.key_image)),
        Token::Array(
            lsag.ring
                .iter()
                .map(|point| Token::Uint(affine_point_to_uint256(point)))
                .collect(),
        ),
    ];
    result.extend(encode(&tokens));
    result
}

fn affine_point_to_uint256(point: &AffinePoint) -> U256 {
    let x_bytes = point.x().to_vec();
    U256::from_big_endian(&x_bytes)
}