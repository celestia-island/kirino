use rand::Rng;

/// Generate a cryptographically random 256-bit hex token (64 hex chars).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
