#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "actix")]
pub mod actix;

/// Parse an `Authorization` header value as a Bearer token.
///
/// RFC 6750 §2.1: the auth-scheme is case-insensitive, so `bearer`,
/// `BEARER` and `Bearer` all name the same scheme — a scheme spelled in
/// another case is a Bearer credential, not a missing one. Returns the
/// token (leading whitespace trimmed); `None` for any other scheme.
pub(crate) fn bearer_token(header_value: &str) -> Option<&str> {
    let (scheme, token) = header_value.split_once(' ')?;
    let token = token.trim_start();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::bearer_token;

    #[test]
    fn scheme_is_case_insensitive() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer abc"), Some("abc"));
        assert_eq!(bearer_token("BEARER abc"), Some("abc"));
        assert_eq!(bearer_token("bEaReR abc"), Some("abc"));
    }

    #[test]
    fn other_schemes_and_garbage_are_refused() {
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Bearer   "), None);
        assert_eq!(bearer_token(""), None);
    }

    #[test]
    fn token_keeps_inner_spacing() {
        // A JWT never contains spaces; trimming only the leading run keeps
        // the parse honest about anything else.
        assert_eq!(bearer_token("Bearer  a b"), Some("a b"));
    }
}
