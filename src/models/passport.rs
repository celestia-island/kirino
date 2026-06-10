use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

use yuuka::derive_enum;

use super::credential::Credential;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MACAddress(pub String);

derive_enum!(
    #[derive(PartialEq, Serialize, Deserialize)]
    #[macros_recursive(serde(rename_all = "snake_case"))]
    pub enum Passport {
        StaticPassword(enum {
            OneTime {
                password: String,
            },
            Permanent {
                password: String,
            },
            Application {
                password: String,
                ref_services: Vec<Uuid>,
            }
        }),
        KeyPair {
            public_key: String,
            provider_ca: Uuid,
        },
        OAuth {
            token: String,
            expires_at: DateTime<Utc>,
            provider_sso: Uuid,
        },
        DynamicPassword(enum {
            TOTP {
                secret: String,
                length: u8,
                period: u8,
            },
            HOTP {
                secret: String,
                length: u8,
                counter: u64,
            },
            Verification {
                session: Uuid,
                expires_at: DateTime<Utc>,
                value: String,
                provider_entity: Uuid,
            },
        }),
        Captcha {
            session: Uuid,
            token: String,
            expires_at: DateTime<Utc>,
            provider_captcha: Uuid,
        },
        Biometric {
            session: Uuid,
            template: Uuid,
            provider_ai: Uuid,
        },
        TemporaryWhitelist(enum {
            ClientSource(enum {
                IPv4(Ipv4Addr),
                IPv6(Ipv6Addr),
                MAC(MACAddress),
            }),
            PreviousCredential(Credential),
        })
    }
);
