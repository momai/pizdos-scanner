mod init;
mod ipinfo_providers;
mod ipinfo;
mod utils;
mod geoip;
mod icmp;
mod tcp_ping;
mod xray_geoip;

use anyhow::Result;
use colored::Colorize;
use std::path::Path;
use std::time::Duration;
use clap::{
    Parser,
    Subcommand,
};
use tokio::time::sleep;
use crate::ipinfo::get_providers_info;
use crate::init::{Config, ConfigSocketType};
use crate::icmp::{app, ping_subnet_matrix_rayon, scan_networks, SubnetScanFile};
use crate::geoip::download_dbs;
use crate::utils::{get_current_ip, write_final_ip_lists_from_jsonl};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to custom config file. Default: config.toml
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Initialize program
    #[arg(long)]
    init: bool,

    /// Update db files
    #[arg(long)]
    update: bool,

    /// Command to execute
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Ping subnets from config or custom file
    Subnets {
        /// Custom file with subnets
        #[arg(value_name = "subnets_file")]
        scan_file: Option<String>,
    },
    /// Ping /24 subnet
    Subnet {
        /// Some ip from /24 subnet
        #[arg(value_name = "ip")]
        ip: String,
        /// Command to execute
        #[command(subcommand)]
        subcommand: Option<SubnetSubCommand>,
    },
    /// Get current IP (whitelisted mode)
    Myip,
    /// Get info about IP
    Info {
        /// IP or domain to get info
        #[arg(value_name = "ip")]
        ip: String,
    },
    Test {
        /// IP or domain to get info
        #[arg(value_name = "ip")]
        ip: Option<String>,
        /// Ports to test
        #[arg(value_name = "ports")]
        ports: Option<Vec<u16>>,
        /// SNI host for curl-like HTTPS probe
        #[arg(long)]
        sni: Option<String>,
    },
    /// List codes available in Xray/V2Ray geoip.dat
    GeoipList,
    /// Scan IPv4 CIDR lists from Xray/V2Ray geoip.dat
    GeoipScan {
        /// Override geoip codes from config
        #[arg(value_name = "codes")]
        codes: Vec<String>,
    },
    /// Build final alive/rejected TXT lists from scanner JSONL
    Finalize {
        /// Scanner JSONL result file
        #[arg(value_name = "jsonl_file")]
        jsonl_file: String,
    },
}

#[derive(Subcommand, Debug)]
enum SubnetSubCommand {
    /// Add getting info about IP
    Full
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

    let config_path = &args.config;
    let config: Config = Config::load(config_path)?;

    if args.update {
        download_dbs(&config).await?;
    }

    match args.command {
        Some(Command::Subnets { scan_file }) => {

            rayon::ThreadPoolBuilder::new()
                .num_threads(500)
                .build_global()?;

            match scan_file {
                Some(file_path) => {

                    let path = Path::new(&file_path);
                    let task = SubnetScanFile {
                        file_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
                        file_path: file_path.clone()
                    };
                    app(&config, task).await?;
                },
                None => {
                    let task = SubnetScanFile {
                        file_name: String::new(),
                        file_path: String::new()
                    };
                    app(&config, task).await?;
                }
            };
        },
        Some(Command::Subnet { ip, subcommand }) => {

            rayon::ThreadPoolBuilder::new()
                .num_threads(500)
                .build_global()?;

            let tcp_ports = config.tcp_ports();
            let ip = ping_subnet_matrix_rayon(
                ip.as_str(),
                2,
                &config.socket_type.as_ref().unwrap(),
                &config.ping_type,
                &tcp_ports,
                config.tcp_sni_host.as_deref(),
                config.network_interface(),
            ).await?;

            match subcommand {
                Some(SubnetSubCommand::Full) => {
                    get_providers_info(&config, &ip).await?;
                },
                None => {}
            }
        },
        Some(Command::Myip) => {
            let ip = get_current_ip().await;
            match ip {
                Ok(ip) => println!("current ip: {}", ip),
                Err(e) => println!("ERR {}", e),
            }
        },
        Some(Command::Info { ip }) => {
            get_providers_info(&config, &ip).await?;

            let ip_parsed: std::net::IpAddr = ip.parse()?;

            let hostname = dns_lookup::lookup_addr(&ip_parsed.clone()).unwrap_or_else(|_| "None".to_string());
            println!("PTR for {} - {}", ip, hostname);

            let socket = match &config.socket_type {
                Some(ConfigSocketType::DGRAM) => ping::DGRAM,
                Some(ConfigSocketType::RAW) => ping::RAW,
                None => ping::DGRAM,
            };

            let mut pings: Vec<Duration> = vec![];

            for _ in 0..3 {
                let mut ping = ping::new(ip_parsed);
                ping.socket_type(socket).timeout(Duration::from_secs(1));
                #[cfg(any(target_os = "linux", target_os = "android"))]
                if let Some(network_interface) = config.network_interface() {
                    ping.bind_device(network_interface);
                }

                match ping.send() {
                    Ok(r) => {
                        pings.push(r.rtt);
                    },
                    Err(_e) => { },
                }
                sleep(Duration::from_millis(300)).await
            }

            println!("PING for {} - {:?}", ip_parsed, pings);

        },
        Some(Command::Test { ip, ports, sni }) => {
            if ip.is_some() && ports.is_some() {
                tcp_ping::test_tcp_ping(
                    &String::from(ip.unwrap()),
                    &ports.unwrap(),
                    sni.as_deref(),
                    config.network_interface(),
                ).await?;
            } else {
                println!("Please specify ip and ports");
            }
        },
        Some(Command::GeoipList) => {
            let codes = xray_geoip::list_codes(config.geoip_dat_path())?;
            println!("{:<24} {:>10} {:>10} {:>10}", "code", "cidr", "ipv4", "ipv6");
            println!("{}", "-".repeat(60));
            for code in codes {
                println!(
                    "{:<24} {:>10} {:>10} {:>10}",
                    code.code, code.cidr_count, code.ipv4_count, code.ipv6_count
                );
            }
        },
        Some(Command::GeoipScan { codes }) => {
            rayon::ThreadPoolBuilder::new()
                .num_threads(500)
                .build_global()?;

            let codes = if codes.is_empty() {
                config.geoip_codes()
            } else {
                codes
            };

            if codes.is_empty() {
                anyhow::bail!("geoip_codes is empty; set it in config or pass codes to geoip-scan");
            }

            let loaded = xray_geoip::load_ipv4_cidrs(config.geoip_dat_path(), &codes)?;
            if loaded.matched_codes.is_empty() {
                anyhow::bail!("No matching geoip codes found: {:?}", codes);
            }

            println!(
                "{}",
                format!(
                    "loaded {} IPv4 CIDR from {:?}, skipped IPv6 {}",
                    loaded.networks.len(),
                    loaded.matched_codes,
                    loaded.skipped_ipv6
                )
                .cyan()
            );

            let networks = loaded.networks.iter().map(ToString::to_string).collect();
            let scan_name = format!("geoip_{}", loaded.matched_codes.join("_").to_lowercase());
            scan_networks(&config, &scan_name, networks).await?;
        },
        Some(Command::Finalize { jsonl_file }) => {
            let (alive_file, rejected_file, alive_count, rejected_count) =
                write_final_ip_lists_from_jsonl(&jsonl_file)?;
            println!("Alive IPs: {} -> {}", alive_count, alive_file);
            println!("Rejected IPs: {} -> {}", rejected_count, rejected_file);
        },
        None => {

            if !args.init && !args.update {
                println!("No command specified");
            }

        }
    }
    Ok(())
}