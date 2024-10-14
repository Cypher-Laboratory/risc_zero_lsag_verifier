use hex::{self, FromHex};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint, EncodedPoint};

/// Serializes an AffinePoint to a compressed hexadecimal string
pub fn serialize_point(point: AffinePoint) -> Result<String, String> {
    let encoded = point.to_encoded_point(false); // Uncompressed
    let x_bytes = encoded
        .x()
        .ok_or_else(|| "x coordinate missing".to_string())?;
    let y_bytes = encoded
        .y()
        .ok_or_else(|| "y coordinate missing".to_string())?;
    let x_hex_padded = format!("{:0>64}", hex::encode(x_bytes));
    let prefix = if (y_bytes
        .last()
        .ok_or_else(|| "y coordinate is empty".to_string())?
        & 1)
        == 0
    {
        "02"
    } else {
        "03"
    };
    Ok(format!("{}{}", prefix, x_hex_padded))
}

/// Deserialize a compressed hexadecimal string to an AffinePoint
pub fn deserialize_point(hex_str: &str) -> Result<AffinePoint, String> {
    let bytes = Vec::from_hex(hex_str).map_err(|_| "Invalid hexadecimal string".to_string())?;
    if bytes.len() != 33 {
        return Err("Invalid length for a compressed point".to_string());
    }
    let encoded_point = EncodedPoint::from_bytes(&bytes)
        .map_err(|_| "Invalid compressed point encoding".to_string())?;
    let affine_point = AffinePoint::from_encoded_point(&encoded_point);
    if affine_point.is_some().into() {
        Ok(affine_point.unwrap())
    } else {
        Err("Failed to parse AffinePoint from encoded point".to_string())
    }
}
