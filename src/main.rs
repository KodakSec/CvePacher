mod scanner;
mod updater;
mod models;
mod error;

use clap::{Parser, Subcommand};
use colored::*;
use log::info;
use crate::scanner::SystemScanner;
use crate::updater::UpdateChecker;
use crate::error::ScannerError;

const ASCII_BANNER: &str = r#"
_________                  __________           __           .__                     
\_   ___ \ ___  __  ____   \______   \_____   _/  |_   ____  |  |__    ____  _______ 
/    \  \/ \  \/ /_/ __ \   |     ___/\__  \  \   __\_/ ___\ |  |  \ _/ __ \ \_  __ \
\     \____ \   / \  ___/   |    |     / __ \_ |  |  \  \___ |   Y  \\  ___/  |  | \/
 \______  /  \_/   \___  >  |____|    (____  / |__|   \___  >|___|  / \___  > |__|   
        \/             \/                  \/             \/      \/      \/         
OpenSource Project Github.com/KodakSec
"#;

#[derive(Parser)]
#[command(name = "cvepatcher")]
#[command(about = "Windows CVE Scanner and Patcher", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[arg(short, long)]
        verbose: bool,
        #[arg(short, long)]
        json: bool,
    },
    CheckUpdates,
}

#[tokio::main]
async fn main() -> Result<(), ScannerError> {
    env_logger::init();
    println!("{}", ASCII_BANNER.bright_blue());
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { verbose, json } => {
            println!("{}", "[+] Starting system scan...".green());
            let scanner = SystemScanner::new();
            let results = scanner.scan(verbose).await?;
            
            if json {
                let json = serde_json::to_string_pretty(&results)?;
                std::fs::write("scan_results.json", json)?;
                println!("[+] Results exported to scan_results.json");
            } else {
                display_results(&results);
            }
        }
        Commands::CheckUpdates => {
            println!("{}", "[+] Checking for security updates...".green());
            let updater = UpdateChecker::new();
            let updates = updater.check_updates().await?;
            display_updates(&updates);
        }
    }

    Ok(())
}

fn display_results(results: &scanner::ScanResults) {
    println!("\n{}", "Scan Results:".bold());
    println!("Windows Version: {}", results.windows_version);
    println!("\nVulnerabilities Found: {}", results.vulnerabilities.len());
    
    for vuln in &results.vulnerabilities {
        println!("\n{}", "=".repeat(50));
        println!("CVE: {}", vuln.cve_id.red());
        println!("Severity: {}", get_severity_colored(&vuln.severity));
        println!("Description: {}", vuln.description);
        println!("Status: {}", if vuln.patched { "Patched".green() } else { "Unpatched".red() });
    }
}

fn display_updates(updates: &[updater::UpdateInfo]) {
    println!("\n{}", "Available Updates:".bold());
    for update in updates {
        println!("\n{}", "-".repeat(50));
        println!("KB: {}", update.kb_number);
        println!("Title: {}", update.title);
        println!("Type: {}", update.update_type);
    }
}

fn get_severity_colored(severity: &str) -> colored::ColoredString {
    match severity.to_lowercase().as_str() {
        "critical" => severity.red().bold(),
        "high" => severity.red(),
        "medium" => severity.yellow(),
        "low" => severity.green(),
        _ => severity.normal(),
    }
}
