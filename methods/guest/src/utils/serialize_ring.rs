use k256::AffinePoint;

use super::serialize_point::{deserialize_point, serialize_point};

/// Serializes a ring of points into a string.
/// converts the points to strings and concatenates them.
pub fn serialize_ring(ring: &[AffinePoint]) -> Result<String, String> {
    let mut serialized = String::new();
    for point in ring {
        let point_str =
            serialize_point(*point).map_err(|e| format!("Failed to serialize point: {}", e))?;
        serialized.push_str(&point_str);
    }
    Ok(serialized)
}

pub fn deserialize_ring(ring: &[String]) -> Result<Vec<AffinePoint>, String> {
    let mut deserialized_points = Vec::new();

    for point in ring {
        let deserialized_point = deserialize_point(&point)?;
        deserialized_points.push(deserialized_point);
    }

    Ok(deserialized_points)
}
