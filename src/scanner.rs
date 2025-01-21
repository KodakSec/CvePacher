use crate::error::ScannerError;
use crate::models::{SystemInfo, Vulnerability};
use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOEXW};
use windows::Win32::Foundation::BOOL;
use indicatif::ProgressBar;
use serde::{Serialize, Deserialize};
use log::info;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResults {
    pub windows_version: String,
    pub system_info: SystemInfo,
    pub vulnerabilities: Vec<Vulnerability>,
    pub scan_date: String,
}

pub struct SystemScanner {
    client: reqwest::Client,
}

impl SystemScanner {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn scan(&self, verbose: bool) -> Result<ScanResults, ScannerError> {
        let system_info = self.get_system_info()?;
        
        if verbose {
            info!("Système détecté: {:?}", system_info);
        }

        let vulnerabilities = self.fetch_vulnerabilities(&system_info).await?;
        
        Ok(ScanResults {
            windows_version: system_info.windows_version.clone(),
            system_info,
            vulnerabilities,
            scan_date: chrono::Local::now().to_rfc3339(),
        })
    }

    fn get_system_info(&self) -> Result<SystemInfo, ScannerError> {
        unsafe {
            let mut version_info: OSVERSIONINFOEXW = std::mem::zeroed();
            version_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
            
            let result = GetVersionExW(&mut version_info as *mut _ as *mut _);
            if result.as_bool() {
                Ok(SystemInfo {
                    windows_version: format!(
                        "{}.{}", 
                        version_info.dwMajorVersion,
                        version_info.dwMinorVersion
                    ),
                    build_number: version_info.dwBuildNumber.to_string(),
                    architecture: std::env::consts::ARCH.to_string(),
                    installed_updates: self.get_installed_updates()?,
                })
            } else {
                Err(ScannerError::WindowsApiError("Impossible d'obtenir la version de Windows".into()))
            }
        }
    }

    fn get_installed_updates(&self) -> Result<Vec<String>, ScannerError> {
        // TODO: Implémenter la récupération des mises à jour installées via WMI
        Ok(vec![])
    }

    async fn fetch_vulnerabilities(&self, system_info: &SystemInfo) -> Result<Vec<Vulnerability>, ScannerError> {
        let pb = ProgressBar::new_spinner();
        pb.set_message("Recherche des vulnérabilités...");

        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Windows {}",
            system_info.windows_version
        );

        let _response = self.client.get(&url).send().await?;
        // TODO: Implémenter le parsing de la réponse
        let vulns: Vec<Vulnerability> = vec![];

        pb.finish_with_message("Recherche terminée");
        Ok(vulns)
    }
} 