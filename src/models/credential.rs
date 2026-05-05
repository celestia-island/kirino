use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use yuuka::derive_enum;

derive_enum!(
    #[derive(PartialEq, Serialize, Deserialize)]
    #[macros_recursive(serde(rename_all = "snake_case"))]
    pub enum Credential {
        OneTime {
            token: String,
            expires_at: DateTime<Utc>,
        },
        Basic {
            token: String,
            expires_at: DateTime<Utc>,
        },
        Service {
            token: String,
            ref_user: Uuid,
        },
    }
);
