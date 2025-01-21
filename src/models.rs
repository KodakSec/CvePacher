use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve_id: String,
    pub severity: String,
    pub description: String,
    pub patched: bool,
    pub published_date: String,
    pub cvss_score: Option<f32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemInfo {
    pub windows_version: String,
    pub build_number: String,
    pub architecture: String,
    pub installed_updates: Vec<String>,
} 