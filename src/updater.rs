use crate::error::ScannerError;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub kb_number: String,
    pub title: String,
    pub update_type: String,
    pub installation_date: Option<String>,
}

pub struct UpdateChecker;

impl UpdateChecker {
    pub fn new() -> Self {
        Self
    }

    pub async fn check_updates(&self) -> Result<Vec<UpdateInfo>, ScannerError> {
        Ok(vec![])
    }
} 