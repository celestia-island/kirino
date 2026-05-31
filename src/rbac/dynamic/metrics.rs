use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use super::delegator::Delegator;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionCategory {
    ReadOnly,
    StateWrite,
    FileWrite,
    NetworkEgress,
    ProcessExec,
    ContainerLifecycle,
    PrivilegedOp,
}

impl ActionCategory {
    pub fn base_weight(&self) -> f64 {
        match self {
            ActionCategory::ReadOnly => 0.1,
            ActionCategory::StateWrite => 0.3,
            ActionCategory::FileWrite => 0.5,
            ActionCategory::NetworkEgress => 0.7,
            ActionCategory::ProcessExec => 0.8,
            ActionCategory::ContainerLifecycle => 0.9,
            ActionCategory::PrivilegedOp => 1.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSensitivity {
    pub action: String,
    pub category: ActionCategory,
    pub base_weight: f64,
}

impl ActionSensitivity {
    pub fn new(action: impl Into<String>, category: ActionCategory) -> Self {
        let bw = category.base_weight();
        Self {
            action: action.into(),
            category,
            base_weight: bw,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub delegator: Delegator,
    pub action: String,
    pub category: ActionCategory,
    pub parameters: BTreeMap<String, Value>,
    pub resource_path: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl ActionRequest {
    pub fn simple(
        delegator: Delegator,
        action: impl Into<String>,
        category: ActionCategory,
    ) -> Self {
        Self {
            delegator,
            action: action.into(),
            category,
            parameters: BTreeMap::new(),
            resource_path: None,
            timestamp: Utc::now(),
        }
    }

    pub fn with_resource(mut self, path: impl Into<String>) -> Self {
        self.resource_path = Some(path.into());
        self
    }

    pub fn with_parameters(mut self, params: BTreeMap<String, Value>) -> Self {
        self.parameters = params;
        self
    }
}
