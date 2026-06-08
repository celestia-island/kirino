use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegatorType {
    Human,
    Agent,
    SubAgent,
    ExternalSystem,
    Scheduler,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegator {
    pub id: String,
    pub delegator_type: DelegatorType,
    pub session_badge: String,
    pub parent_id: Option<String>,
}

impl Delegator {
    pub fn human(id: impl Into<String>, session_badge: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            delegator_type: DelegatorType::Human,
            session_badge: session_badge.into(),
            parent_id: None,
        }
    }

    pub fn agent(id: impl Into<String>, session_badge: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            delegator_type: DelegatorType::Agent,
            session_badge: session_badge.into(),
            parent_id: None,
        }
    }

    pub fn sub_agent(
        id: impl Into<String>,
        session_badge: impl Into<String>,
        parent_id: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            delegator_type: DelegatorType::SubAgent,
            session_badge: session_badge.into(),
            parent_id: Some(parent_id.into()),
        }
    }

    #[must_use]
    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }
}
