use std::{fs, path::Path};

use anyhow::Context;

use crate::{
    init::{Config, ConfigPingType},
    scan_state::{build_job_id, load_state, state_path},
    scanner,
    utils::{parse_cidr_lines, write_icmp_ip_list_from_jsonl}, xray_geoip,
};

pub async fn run_icmp_fast(config: &Config, args: &[String]) -> anyhow::Result<()> {
    let (scan_name, networks) = if args.is_empty() {
        ("icmp_fast_subnets".to_string(), config.subnets.clone())
    } else {
        match args[0].as_str() {
            "geoip" | "geoip-scan" => {
                let codes = if args.len() > 1 {
                    args[1..].to_vec()
                } else {
                    config.geoip_codes()
                };
                if codes.is_empty() {
                    anyhow::bail!("icmp-fast geoip: codes are empty; pass codes or set geoip_codes in config");
                }
                let loaded = xray_geoip::load_ipv4_cidrs(config.geoip_dat_path(), &codes)?;
                if loaded.matched_codes.is_empty() {
                    anyhow::bail!("No matching geoip codes found: {:?}", codes);
                }
                (
                    format!("icmp_fast_geoip_{}", loaded.matched_codes.join("_").to_lowercase()),
                    loaded.networks.iter().map(ToString::to_string).collect(),
                )
            }
            "subnets" => {
                if args.len() > 1 {
                    let file_path = &args[1];
                    let path = Path::new(file_path);
                    let content = fs::read_to_string(file_path)?;
                    (
                        format!("icmp_fast_{}", path.file_name().unwrap_or_default().to_string_lossy()),
                        parse_cidr_lines(&content),
                    )
                } else {
                    ("icmp_fast_subnets".to_string(), config.subnets.clone())
                }
            }
            file_path => {
                let path = Path::new(file_path);
                let content = fs::read_to_string(file_path)?;
                (
                    format!("icmp_fast_{}", path.file_name().unwrap_or_default().to_string_lossy()),
                    parse_cidr_lines(&content),
                )
            }
        }
    };

    if networks.is_empty() {
        anyhow::bail!("No CIDR networks to scan (config.subnets/scan_file is empty)");
    }

    let mut icmp_config = config.clone();
    icmp_config.ping_type = vec![ConfigPingType::ICMP];
    scanner::scan_networks(&icmp_config, &scan_name, networks.clone()).await?;

    let job_id = build_job_id(&icmp_config, &scan_name, &networks);
    let state_file = state_path(&icmp_config, &job_id);
    let state = load_state(&state_file)?
        .with_context(|| format!("Scan state not found: {}", state_file.display()))?;
    let (icmp_file, icmp_count) = write_icmp_ip_list_from_jsonl(&state.result_jsonl)?;

    println!("ICMP alive IPs: {} -> {}", icmp_count, icmp_file);
    println!(
        "Next step: pizdos-scanner tcp-scan-file {} {}",
        icmp_file,
        icmp_config
            .tcp_ports()
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    );

    Ok(())
}
