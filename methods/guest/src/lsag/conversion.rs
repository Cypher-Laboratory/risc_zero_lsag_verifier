use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct StringifiedLsag {
    pub message: String,
    pub ring: Vec<String>,
    pub c: String,
    pub responses: Vec<String>,
    pub keyImage: String,
    pub linkabilityFlag: String,
}

pub fn convert_string_to_json(json_str: &str) -> StringifiedLsag {
    serde_json::from_str(json_str).unwrap()
}
