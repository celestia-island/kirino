use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub subject_id: String,
    pub subject_type: String,
    pub permission: String,
    pub endpoint: String,
    pub granted: bool,
    pub created_at: DateTime<Utc>,
}

pub trait AuditLogger: Send + Sync {
    fn log(&self, entry: AuditEntry);
    fn recent(&self, limit: usize) -> Vec<AuditEntry>;
}

pub struct InMemoryAuditLogger {
    entries: tokio::sync::RwLock<Vec<AuditEntry>>,
}

impl InMemoryAuditLogger {
    pub fn new() -> Self {
        Self {
            entries: tokio::sync::RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger for InMemoryAuditLogger {
    fn log(&self, entry: AuditEntry) {
        let mut entries = self.entries.blocking_write();
        entries.push(entry);
    }

    fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        let entries = self.entries.blocking_read();
        entries.iter().rev().take(limit).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log() {
        let logger = InMemoryAuditLogger::new();

        logger.log(AuditEntry {
            subject_id: "user1".to_string(),
            subject_type: "user".to_string(),
            permission: "system_write".to_string(),
            endpoint: "/api/admin".to_string(),
            granted: true,
            created_at: Utc::now(),
        });

        logger.log(AuditEntry {
            subject_id: "user2".to_string(),
            subject_type: "user".to_string(),
            permission: "system_write".to_string(),
            endpoint: "/api/admin".to_string(),
            granted: false,
            created_at: Utc::now(),
        });

        let recent = logger.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].subject_id, "user2");
        assert!(!recent[0].granted);
        assert!(recent[1].granted);
    }

    #[test]
    fn test_audit_log_limit() {
        let logger = InMemoryAuditLogger::new();
        for i in 0..10 {
            logger.log(AuditEntry {
                subject_id: format!("user{}", i),
                subject_type: "user".to_string(),
                permission: "read".to_string(),
                endpoint: String::new(),
                granted: true,
                created_at: Utc::now(),
            });
        }
        let recent = logger.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].subject_id, "user9");
    }
}
