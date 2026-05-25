use std::{collections::BTreeSet, fs, path::Path, time::Duration};

use anyhow::Result;

use crate::{init::Config, tcp_ping, utils::parse_ip_lines};

pub fn run_tcp_scan_file(
    config: &Config,
    ips_file: String,
    ports: Vec<u16>,
    sni: Option<String>,
) -> Result<()> {
    if ports.is_empty() {
        anyhow::bail!("Please specify ports, e.g. tcp-scan-file ips.txt 80 443");
    }

    let content = fs::read_to_string(&ips_file)?;
    let ip_lines = parse_ip_lines(&content);
    if ip_lines.is_empty() {
        anyhow::bail!("No IPs found in {}", ips_file);
    }

    let mut alive_ips = BTreeSet::new();
    let mut rejected_ips = BTreeSet::new();
    for ip_line in ip_lines {
        let ip = tcp_ping::string_to_ip(&ip_line)?;
        let probes = tcp_ping::test_tcp_ping_ip(
            ip,
            &ports,
            sni.as_deref(),
            config.network_interface(),
            Duration::from_secs(2),
        );
        let mut has_alive = false;
        let mut has_rejected = false;
        for (_, status, _) in probes {
            if status.is_alive() {
                has_alive = true;
            }
            if status == tcp_ping::TcpProbeStatus::Rejected {
                has_rejected = true;
            }
        }
        if has_rejected {
            rejected_ips.insert(ip);
        }
        if has_alive && !has_rejected {
            alive_ips.insert(ip);
        }
    }

    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let base = Path::new(config.results_dir()).join(format!("tcp_file_{ts}"));
    let alive_path = base.with_file_name(format!("tcp_file_{ts}_alive.txt"));
    let rejected_path = base.with_file_name(format!("tcp_file_{ts}_rejected.txt"));
    fs::write(
        &alive_path,
        alive_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )?;
    fs::write(
        &rejected_path,
        rejected_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )?;

    println!("TCP alive IPs: {} -> {}", alive_ips.len(), alive_path.display());
    println!(
        "TCP rejected IPs: {} -> {}",
        rejected_ips.len(),
        rejected_path.display()
    );
    Ok(())
}
