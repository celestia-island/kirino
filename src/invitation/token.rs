use rand::RngExt;

/// Generate a cryptographically random 256-bit hex token (64 hex chars).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
