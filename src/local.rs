//! 调用方自备密钥与 claims 的 JWT 签发/验证原语（HS256）。
//!
//! 定位（2026-10-20 结构体检批次4-C）：`TokenManager` 服务云端会话语义（自有
//! claims/permissions/撤销面）；服务层还存在第二类令牌——**应用自有 claims +
//! 调用方派生密钥**（如桌面端的本机令牌、集成流的 pending 令牌）——此前各服务
//! 裸用 `jsonwebtoken` 重复实现签发/验证循环。本模块把这一类收敛为唯一上游原语：
//! 密钥由调用方派生（机器指纹、应用 secret），claims 形状由调用方定义，唯一
//! 强制项是 `exp`（验证必查，含 60s leeway）。
//!
//! 不属于本模块的：非对称密钥、会话/撤销、权限模型——需要那些就用
//! `kirino_session::TokenManager`（session 包，独立版本线）。

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// 签发/验证共用的 claims 约束：必须携带可读的过期时间。
pub trait ExpClaims {
    /// Unix 秒级过期时间。
    fn exp(&self) -> i64;
}

/// HS256 对称密钥的本地 JWT 原语。
#[derive(Clone)]
pub struct LocalJwt {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

/// 本地令牌错误：签发失败、验证失败或 claims 不含 exp。
#[derive(Debug, thiserror::Error)]
pub enum LocalJwtError {
    #[error("local jwt sign failed: {0}")]
    Sign(#[source] jsonwebtoken::errors::Error),
    #[error("local jwt verify failed: {0}")]
    Verify(#[source] jsonwebtoken::errors::Error),
    #[error("local jwt claims must carry a positive exp")]
    MissingExp,
}

impl LocalJwt {
    /// 以对称密钥构造（HS256）。密钥材料由调用方派生与保管。
    pub fn from_secret(secret: impl Into<Vec<u8>>) -> Self {
        let secret = secret.into();
        Self {
            encoding: EncodingKey::from_secret(&secret),
            decoding: DecodingKey::from_secret(&secret),
        }
    }

    /// 签发一枚携带调用方 claims 的令牌；拒绝没有正 `exp` 的 claims
    /// （不带过期的「令牌」是凭据事故的常见起点）。
    pub fn sign<C: Serialize + ExpClaims>(&self, claims: &C) -> Result<String, LocalJwtError> {
        if claims.exp() <= 0 {
            return Err(LocalJwtError::MissingExp);
        }
        jsonwebtoken::encode(&Header::new(Algorithm::HS256), claims, &self.encoding)
            .map_err(LocalJwtError::Sign)
    }

    /// 验证签名与 `exp`（60s leeway），返回完整 claims。
    pub fn verify<C: DeserializeOwned + ExpClaims>(&self, token: &str) -> Result<C, LocalJwtError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 60;
        validation.required_spec_claims.clear();
        let data = jsonwebtoken::decode::<C>(token, &self.decoding, &validation)
            .map_err(LocalJwtError::Verify)?;
        Ok(data.claims)
    }

    /// 只验证签名、宽免 `exp` 的验证路径。
    ///
    /// 宽免只发生在**过期轴**上，不发生在信任轴上：签名仍必须有效，其余
    /// 一概不放松——本原语的唯一强制项就是 `exp`，所以宽免的也只有它。
    /// 存在的理由是**续期式**流程：凭一枚已过期的出示令牌换发新令牌，
    /// 且换发前已在带外重新核查主体生命周期（仓内消费者 =
    /// `auth::visitor` 的滚动续期）。一切出示路径（presentation）的校验
    /// 仍必须走严格 [`Self::verify`]；说不出自己流程里带外复查的是哪道
    /// 生命周期门的调用方，没有资格调用本方法。
    pub fn verify_lenient<C: DeserializeOwned + ExpClaims>(
        &self,
        token: &str,
    ) -> Result<C, LocalJwtError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        let data = jsonwebtoken::decode::<C>(token, &self.decoding, &validation)
            .map_err(LocalJwtError::Verify)?;
        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct AppClaims {
        sub: String,
        custom: String,
        exp: i64,
    }

    impl ExpClaims for AppClaims {
        fn exp(&self) -> i64 {
            self.exp
        }
    }

    fn claims(exp: i64) -> AppClaims {
        AppClaims {
            sub: "device-7".into(),
            custom: "machine-token".into(),
            exp,
        }
    }

    #[test]
    fn round_trips_caller_defined_claims() {
        let jwt = LocalJwt::from_secret(b"machine-fingerprint-derived");
        let exp = chrono::Utc::now().timestamp() + 300;
        let token = jwt.sign(&claims(exp)).unwrap();
        let back = jwt.verify::<AppClaims>(&token).unwrap();
        assert_eq!(back, claims(exp), "caller claims survive the wire");
    }

    #[test]
    fn expired_tokens_are_rejected() {
        let jwt = LocalJwt::from_secret(b"k");
        let stale = jwt
            .sign(&claims(chrono::Utc::now().timestamp() - 120))
            .unwrap();
        assert!(matches!(
            jwt.verify::<AppClaims>(&stale),
            Err(LocalJwtError::Verify(_))
        ));
    }

    #[test]
    fn tampered_signature_and_wrong_key_are_rejected() {
        let signer = LocalJwt::from_secret(b"alpha");
        let other = LocalJwt::from_secret(b"beta");
        let exp = chrono::Utc::now().timestamp() + 60;
        let token = signer.sign(&claims(exp)).unwrap();
        assert!(other.verify::<AppClaims>(&token).is_err());
        let mut forged = token.clone();
        forged.replace_range(0..1, "X");
        assert!(signer.verify::<AppClaims>(&forged).is_err());
    }

    #[test]
    fn signing_refuses_claims_without_a_positive_exp() {
        let jwt = LocalJwt::from_secret(b"k");
        assert!(matches!(
            jwt.sign(&claims(0)),
            Err(LocalJwtError::MissingExp)
        ));
        assert!(matches!(
            jwt.sign(&claims(-5)),
            Err(LocalJwtError::MissingExp)
        ));
    }

    #[test]
    fn lenient_verify_forgives_only_expiry() {
        // The renewal-style contract: an expired token stays rejected by the
        // strict path but decodes through the lenient one, while a broken
        // signature is rejected by BOTH — leniency is an expiry axis, not a
        // trust axis.
        let jwt = LocalJwt::from_secret(b"k");
        let stale = chrono::Utc::now().timestamp() - 300;
        let expired = jwt.sign(&claims(stale)).unwrap();
        assert!(jwt.verify::<AppClaims>(&expired).is_err());
        assert_eq!(
            jwt.verify_lenient::<AppClaims>(&expired).unwrap(),
            claims(stale)
        );

        // A forged signature is not forgiven.
        let mut forged = expired.clone();
        forged.replace_range(0..1, "X");
        assert!(jwt.verify_lenient::<AppClaims>(&forged).is_err());
        // A different key is not forgiven either.
        let other = LocalJwt::from_secret(b"other-key");
        assert!(other.verify_lenient::<AppClaims>(&expired).is_err());
    }
}
