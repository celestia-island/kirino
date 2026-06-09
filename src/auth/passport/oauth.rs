#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct OAuthVerifier {
    #[allow(dead_code)]
    provider: String,
    #[allow(dead_code)]
    client_id: String,
}

impl OAuthVerifier {
    #[must_use]
    pub fn new(provider: String, client_id: String) -> Self {
        Self {
            provider,
            client_id,
        }
    }

    pub fn verify_token(&self, _access_token: &str) -> Result<OAuthClaims> {
        unimplemented!("OAuth token verification")
    }

    pub fn authorization_url(&self, _redirect_uri: &str, _state: &str) -> String {
        unimplemented!("OAuth authorization URL generation")
    }
}

pub struct OAuthClaims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
}
