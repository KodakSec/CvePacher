use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Erreur système: {0}")]
    SystemError(String),
    
    #[error("Erreur réseau: {0}")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("Erreur IO: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Erreur de sérialisation: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Erreur Windows API: {0}")]
    WindowsApiError(String),
} 