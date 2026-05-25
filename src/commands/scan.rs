use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::{
    geoip::download_dbs,
    icmp::{app, ping_subnet_matrix_rayon, scan_networks, ProbeTuning, SubnetScanFile},
    init::Config,
    ipinfo::get_providers_info,
    xray_geoip,
};

fn init_rayon_pool() -> Result<()> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(500)
        .build_global()
        .or_else(|e| {
            if e.to_string().contains("already initialized") {
                Ok(())
            } else {
                Err(e)
            }
        })?;
    Ok(())
}

pub async fn run_subnets(config: &Config, scan_file: Option<String>) -> Result<()> {
    init_rayon_pool()?;
    match scan_file {
        Some(file_path) => {
            let path = Path::new(&file_path);
            let task = SubnetScanFile {
                file_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
                file_path: file_path.clone(),
            };
            app(config, task).await?;
        }
        None => {
            let task = SubnetScanFile {
                file_name: String::new(),
                file_path: String::new(),
            };
            app(config, task).await?;
        }
    }
    Ok(())
}

pub async fn run_subnet(config: &Config, ip: String, full: bool) -> Result<()> {
    init_rayon_pool()?;
    let tcp_ports = config.tcp_ports();
    let ip = ping_subnet_matrix_rayon(
        ip.as_str(),
        ProbeTuning::from_config(config),
        &config.socket_type.as_ref().unwrap(),
        &config.ping_type,
        &tcp_ports,
        config.tcp_sni_host.as_deref(),
        config.network_interface(),
    )
    .await?;
    if full {
        get_providers_info(config, &ip).await?;
    }
    Ok(())
}

pub async fn run_geoip_scan(config: &Config, codes: Vec<String>) -> Result<()> {
    init_rayon_pool()?;
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
    scan_networks(config, &scan_name, networks).await?;
    Ok(())
}

pub async fn run_update(config: &Config) -> Result<()> {
    download_dbs(config).await?;
    Ok(())
}

pub fn run_geoip_list(config: &Config) -> Result<()> {
    let codes = xray_geoip::list_codes(config.geoip_dat_path())?;
    println!("{:<24} {:>10} {:>10} {:>10}", "code", "cidr", "ipv4", "ipv6");
    println!("{}", "-".repeat(60));
    for code in codes {
        println!(
            "{:<24} {:>10} {:>10} {:>10}",
            code.code, code.cidr_count, code.ipv4_count, code.ipv6_count
        );
    }
    Ok(())
}
