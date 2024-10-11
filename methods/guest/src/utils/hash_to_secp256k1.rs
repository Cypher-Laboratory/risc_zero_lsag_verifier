use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::elliptic_curve::AffinePoint;
use k256::Secp256k1;
use sha2::Sha256;

pub fn hash_to_secp256k1(message: &str) -> Result<AffinePoint<Secp256k1>, String> {
    let msg = message.as_bytes();

    const DST: &[u8] = b"secp256k1_XMD:SHA-256_SSWU_RO_";

    // Wrap msg and DST in slices of byte slices (to &[&[u8]])
    let point = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg], &[DST])
        .map_err(|_| "Failed to hash message to secp256k1")?;

    Ok(point.to_affine())
}
