use ethabi::ethereum_types::U256;
use ethabi::{encode, Token};
use k256::{
    elliptic_curve::point::AffineCoordinates, elliptic_curve::sec1::ToEncodedPoint, AffinePoint,
};
use sha2::{Digest, Sha256};

struct PointCoordinates {
    x: U256,
    y: U256,
}

#[derive(Debug)]
pub struct MinimalLsag<'a> {
    pub message: &'a str,
    pub key_image: AffinePoint,
    pub linkability_flag: Option<&'a str>,
    pub ring: Vec<AffinePoint>,
}

// Convert a lsag to a minimal LSAG and return the sha256 digest of the data
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

// ABI encode the minimal lsag
fn abi_encode_minimal_lsag(lsag: &MinimalLsag) -> Vec<u8> {
    //set the offset
    let mut result = vec![0u8; 32];
    result[31] = 32u8;

    // Convert key_image to point coordinates
    let key_image_coords = affine_point_to_coordinates(&lsag.key_image);

    // Convert ring points to array of point coordinates
    let ring_points: Vec<Token> = lsag
        .ring
        .iter()
        .map(|point| {
            let coords = affine_point_to_coordinates(point);
            Token::Tuple(vec![Token::Uint(coords.x), Token::Uint(coords.y)])
        })
        .collect();

    let tokens = vec![
        Token::String(lsag.message.to_string()),
        Token::String(lsag.linkability_flag.unwrap_or_default().to_string()),
        Token::Tuple(vec![
            Token::Uint(key_image_coords.x),
            Token::Uint(key_image_coords.y),
        ]),
        Token::Array(ring_points),
    ];

    result.extend(encode(&tokens));
    result
}

fn affine_point_to_coordinates(point: &AffinePoint) -> PointCoordinates {
    let encoded = point.to_encoded_point(false);

    let x_bytes = encoded.x().unwrap();
    let y_bytes = encoded.y().unwrap();

    PointCoordinates {
        x: U256::from_big_endian(&x_bytes),
        y: U256::from_big_endian(&y_bytes),
    }
}
