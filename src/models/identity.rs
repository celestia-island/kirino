use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use yuuka::derive_enum;

derive_enum!(
    #[derive(PartialEq, Serialize, Deserialize)]
    #[macros_recursive(serde(rename_all = "snake_case"))]
    pub enum Identity {
        Anonymous {
            id: Uuid,
            created_at: DateTime<Utc>,
        },
        Basic {
            id: Uuid,
        },
        Temporary {
            id: Uuid,
            expires_at: DateTime<Utc>,
        },
        Service {
            id: Uuid,
            caller: Uuid,
            created_at: DateTime<Utc>,
        },
    }
);
