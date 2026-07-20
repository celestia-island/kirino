//! Session restore flow using `verify_lenient`.
//!
//! Demonstrates the cookie-based session restore pattern:
//!  1. User logs in → access token stored in httpOnly cookie
//!  2. Page refresh → browser sends cookie (may be expired)
//!  3. Server uses `verify_lenient()` to decode even an expired token
//!     (note: `jsonwebtoken` has a default 60s leeway; `verify_lenient`
//!      disables expiry validation entirely, not just the leeway).
//!  4. After identity is confirmed, issue a fresh token pair.

use std::sync::Arc;
use std::time::Duration;

use kirino_session::{SessionConfig, TokenClaims, TokenManager, TokenType};
use uuid::Uuid;

#[tokio::main]
async fn main() {
    let manager = Arc::new(TokenManager::new(SessionConfig::new("restore-demo-secret")));

    // ── Step 1: Issue an access token with a very short TTL ──
    let claims = TokenClaims::new(
        Uuid::new_v4(),
        "alice".into(),
        TokenType::Access,
        1, // 1-second TTL — expires almost immediately
        "kirino",
    )
    .with_roles(vec!["admin".into()]);

    let token = manager.sign(&claims).unwrap();
    println!("1. Issued token (1s TTL): {}...", &token[..40]);

    // ── Step 2: Wait for it to expire ──
    // jsonwebtoken's default leeway is 60s, so verify() won't reject until
    // ~61s after expiry.  verify_lenient() skips the check immediately.
    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("2. Waited 2s — token TTL was 1s");

    // ── Step 3: verify_lenient() accepts expired tokens ──
    match manager.verify_lenient(&token) {
        Ok(c) => {
            println!(
                "3. verify_lenient() accepted: user={} expired={}",
                c.username,
                c.is_expired(),
            );
            // The caller checks is_expired() and issues a fresh token.
            if c.is_expired() {
                let new_claims = TokenClaims::new(
                    Uuid::parse_str(&c.sub).unwrap_or_default(),
                    c.username.clone(),
                    TokenType::Access,
                    3600,
                    "kirino",
                )
                .with_roles(c.roles);
                let fresh = manager.sign(&new_claims).unwrap();
                println!("4. Issued fresh token (1h TTL): {}...", &fresh[..40]);
            }
        },
        Err(e) => println!("3. verify_lenient() rejected: {e}"),
    }
}
