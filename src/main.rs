mod init;
mod ipinfo_providers;
mod ipinfo;
mod utils;
mod geoip;
mod icmp;
mod scan_state;
mod scanner;
mod tcp_ping;
mod xray_geoip;
mod tui;
mod commands;

use anyhow::Result;
use clap::{
    Parser,
    Subcommand,
};
use std::path::PathBuf;
use crate::commands::{finalize, net, scan, tcp_scan_file};
use crate::init::Config;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Scan /24 subnets from geoip.dat, config, or custom subnet lists",
    after_help = "Examples:
  pizdos-scanner geoip-list
  pizdos-scanner geoip-scan ru
  pizdos-scanner subnets subnets.txt
  pizdos-scanner icmp-fast geoip-scan ru
  pizdos-scanner icmp-fast subnets subnets.txt
  pizdos-scanner tcp-scan-file results/<scan>_icmp_alive.txt 443
  pizdos-scanner subnet 1.1.1.1
  pizdos-scanner test 1.1.1.1 80 443

Use `pizdos-scanner help <command>` for command details."
)]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Create initial local folders/files
    #[arg(long)]
    init: bool,

    /// Update GeoLite2 City/ASN databases from config
    #[arg(long)]
    update: bool,

    /// Command to execute
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan CIDR list from config.toml or a custom file
    Subnets {
        /// File with CIDR list, one network per line. If omitted, uses `subnets` from config.toml
        #[arg(value_name = "subnets_file")]
        scan_file: Option<String>,
    },
    /// Scan one /24 subnet by any IP inside it
    Subnet {
        /// Any IP from the target /24 subnet
        #[arg(value_name = "ip")]
        ip: String,
        /// Optional extra action
        #[command(subcommand)]
        subcommand: Option<SubnetSubCommand>,
    },
    /// Print current public IP
    Myip,
    /// Show provider/GeoIP/PTR info for an IP
    Info {
        /// IP to inspect
        #[arg(value_name = "ip")]
        ip: String,
    },
    /// Test TCP reachability for one IP/domain and selected ports
    Test {
        /// IP or domain to test
        #[arg(value_name = "ip")]
        ip: Option<String>,
        /// Ports to test
        #[arg(value_name = "ports")]
        ports: Option<Vec<u16>>,
        /// SNI host for TLS probe
        #[arg(long)]
        sni: Option<String>,
    },
    /// List codes available in Xray/V2Ray geoip.dat
    GeoipList,
    /// Scan IPv4 CIDR lists from Xray/V2Ray geoip.dat codes
    GeoipScan {
        /// GeoIP codes to scan. If omitted, uses `geoip_codes` from config.toml
        #[arg(value_name = "codes")]
        codes: Vec<String>,
    },
    /// Build final alive/rejected TXT lists from scanner JSONL
    Finalize {
        /// Scanner JSONL result file
        #[arg(value_name = "jsonl_file")]
        jsonl_file: String,
    },
    /// Fast ICMP-only scan + build *_icmp_alive.txt
    IcmpFast {
        /// Source selector:
        /// - empty: use `subnets` from config.toml
        /// - <file>: read CIDR list from file
        /// - geoip-scan <codes...>: load CIDR from geoip.dat codes
        /// - geoip <codes...>: same as geoip-scan
        /// - subnets [file]: from config or file
        #[arg(value_name = "source_or_file")]
        args: Vec<String>,
    },
    /// TCP scan list of IPs from file
    TcpScanFile {
        /// File with IP list, one IP per line
        #[arg(value_name = "ips_file")]
        ips_file: String,
        /// Ports to test
        #[arg(value_name = "ports")]
        ports: Vec<u16>,
        /// SNI host for TLS probe
        #[arg(long)]
        sni: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum SubnetSubCommand {
    /// Also enrich the first alive IP with provider/GeoIP/PTR info
    Full
}

fn resolve_config_path(input: &str) -> (String, bool) {
    let requested = PathBuf::from(input);
    if requested.exists() {
        return (input.to_string(), false);
    }

    if input == "config.toml" {
        if let Ok(home) = std::env::var("HOME") {
            let fallback = PathBuf::from(home).join(".pizdos-scanner").join("config.toml");
            if fallback.exists() {
                return (fallback.to_string_lossy().to_string(), true);
            }
        }
    }

    (input.to_string(), false)
}

#[tokio::main]
async fn main() -> Result<()> {

    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("Panic occurred: {:?}", panic_info);
    }));

    let args = Args::parse();

    if args.init {
        init::init_env()?;
        println!("Initializing complete");
        return Ok(());
    }

    let (config_path, fallback_used) = resolve_config_path(&args.config);
    if fallback_used {
        println!("Using config: {}", config_path);
    }
    let config: Config = Config::load(&config_path)?;

    if args.update {
        scan::run_update(&config).await?;
    }

    match args.command {
        Some(Command::Subnets { scan_file }) => {
            scan::run_subnets(&config, scan_file).await?;
        },
        Some(Command::Subnet { ip, subcommand }) => {
            scan::run_subnet(&config, ip, matches!(subcommand, Some(SubnetSubCommand::Full))).await?;
        },
        Some(Command::Myip) => {
            net::run_myip().await?;
        },
        Some(Command::Info { ip }) => {
            net::run_info(&config, ip).await?;
        },
        Some(Command::Test { ip, ports, sni }) => {
            net::run_test(&config, ip, ports, sni).await?;
        },
        Some(Command::GeoipList) => {
            scan::run_geoip_list(&config)?;
        },
        Some(Command::GeoipScan { codes }) => {
            scan::run_geoip_scan(&config, codes).await?;
        },
        Some(Command::Finalize { jsonl_file }) => {
            finalize::run_finalize(jsonl_file)?;
        },
        Some(Command::IcmpFast { args }) => {
            rayon::ThreadPoolBuilder::new()
                .num_threads(500)
                .build_global()?;
            commands::icmp_fast::run_icmp_fast(&config, &args).await?;
        },
        Some(Command::TcpScanFile { ips_file, ports, sni }) => {
            tcp_scan_file::run_tcp_scan_file(&config, ips_file, ports, sni)?;
        },
        None => {

            if !args.init && !args.update {
                println!("No command specified");
            }

        }
    }
    Ok(())
}