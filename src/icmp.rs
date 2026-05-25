use anyhow::Context;
use ipnetwork::Ipv4Network;
use ping::Ping;
use rayon::prelude::*;
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::Read,
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::time::{sleep, Instant};
use colored::*;
// use futures_util::TryFutureExt;
use crate::init::{
    Config,
    ConfigSocketType,
    ConfigSaveResultFileType,
    ConfigPingType,
    StopOnAvailableConfig,
};
use crate::geoip::{GeoIpService, SubnetInfo};
use crate::utils::{
    append_result_to_csv,
    append_result_to_jsonl,
    append_result_to_txt_lists,
    HostProbeRecord,
    save_results_to_file,
    save_results_to_json,
    SubnetProbeStats,
};
use crate::tcp_ping::TcpProbeStatus;
use crate::tui::{EventLevel, ScanUi, ScanUiConfig, WhitelistInfo};
use crate::init::{ConfigEndpointFailureAction, ConfigStopAction};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default)]
pub struct HostProbeResult {
    pub icmp: bool,
    pub tcp_ports: Vec<u16>,
    pub tcp_rejected_ports: Vec<u16>,
}

impl HostProbeResult {
    pub fn tcp_alive(&self) -> bool {
        !self.tcp_ports.is_empty()
    }
}

fn tcp_ports_with_443(tcp_ports: &[u16]) -> Vec<u16> {
    let mut ports: Vec<u16> = tcp_ports.to_vec();
    if !ports.contains(&443) {
        ports.push(443);
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub async fn ping_subnet_matrix_rayon(
    base_ip: &str,
    attempts: u8,
    socket_type: &ConfigSocketType,
    ping_type: &Vec<ConfigPingType>,
    tcp_ports: &[u16],
    tcp_sni_host: Option<&str>,
    network_interface: Option<&str>,
) -> anyhow::Result<String> {

    let base_octets: Vec<&str> = base_ip.split('.').collect();
    if base_octets.len() != 4 {
        anyhow::bail!("Wrong IP format");
    }

    if !probe_host("127.0.0.1".parse()?, 1, &socket_type, &vec![ConfigPingType::ICMP], &[], None, None).icmp {
        anyhow::bail!("PING («{:?}» socket type) not available", &socket_type);
    }

    let a: u8 = base_octets[0].parse().unwrap_or(0);
    let b: u8 = base_octets[1].parse().unwrap_or(0);
    let c: u8 = base_octets[2].parse().unwrap_or(0);

    println!("\n{} {:?} SUBNET {}.{}.{}.0/24:", " ".repeat(20), ping_type, a, b, c);
    println!("{}", "─".repeat(59).cyan());

    // Using rayon for parallel probe
    let results: Vec<(u8, HostProbeResult)> = (1..=255u8)
        .into_par_iter()
        .map(|i| {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, i));
            let probe = probe_host(ip, attempts, &socket_type, &ping_type, tcp_ports, tcp_sni_host, network_interface);
            (i, probe)
        })
        .collect();

    let mut first_alive_octet: u8 = 1;
    for (octet, probe) in results.clone() {
        if probe.tcp_alive() && octet != 1 {
            first_alive_octet = octet;
            break;
        }
    }
    if first_alive_octet == 1 {
        for (octet, probe) in results.clone() {
            if probe.icmp && octet != 1 {
                first_alive_octet = octet;
                break;
            }
        }
    }
    let first_ip = IpAddr::V4(Ipv4Addr::new(a, b, c, first_alive_octet));
    let hostname = dns_lookup::lookup_addr(&first_ip).unwrap_or_else(|_| "None".to_string());

    let columns = 15;
    let mut count = 0;

    for (octet, probe) in results.clone() {
        if probe.tcp_alive() {
            print!("{:<4}", format!("{}", octet).bright_green().bold());
        } else if probe.icmp {
            print!("{:<4}", format!("{}", octet).yellow().bold());
        } else {
            print!("{:<4}", format!("*").dimmed());
        }

        count += 1;
        if count % columns == 0 {
            println!();
        }
    }

    if count % columns != 0 {
        println!();
    }

    let icmp_count = results.iter().filter(|(_, probe)| probe.icmp).count();
    let tcp_count = results.iter().filter(|(_, probe)| probe.tcp_alive()).count();
    let mut tcp_port_counts: BTreeMap<u16, usize> = BTreeMap::new();
    for (_, probe) in &results {
        for port in &probe.tcp_ports {
            *tcp_port_counts.entry(*port).or_insert(0) += 1;
        }
    }
    let tcp_port_info = tcp_port_counts
        .iter()
        .map(|(port, count)| format!("{port}:{count}"))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "{}{} ICMP: {} | TCP: {} | ports: {} / {}",
        " ".repeat(20),
        "stats".cyan(),
        icmp_count.to_string().yellow(),
        tcp_count.to_string().bright_green(),
        tcp_port_info.green(),
        results.len(),
    );
    println!("{} green=tcp  yellow=icmp-only  *=dead", " ".repeat(20));
    println!("{}", "─".repeat(59).cyan());

    println!("PTR for {} - {}", first_ip, hostname);

    let socket = match socket_type {
        ConfigSocketType::DGRAM => ping::DGRAM,
        ConfigSocketType::RAW => ping::RAW,
    };

    let mut pings: Vec<Duration> = vec![];

    for _ in 0..3 {
        let mut ping = ping::new(first_ip);
        ping.socket_type(socket).timeout(Duration::from_secs(1));
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(network_interface) = network_interface {
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

    println!("PING for {} - {:?}", first_ip, pings);

    Ok(first_ip.to_string())
}

fn split_ipv4_to_24(net: Ipv4Network) -> anyhow::Result<Vec<Ipv4Network>> {
    if net.prefix() >= 24 {
        return Ok(vec![net]);
    }

    let step: u32 = 1 << (32 - 24);
    let start = u32::from(net.network());
    let end = u32::from(net.broadcast());

    let first_subnet_start = start;
    let last_subnet_start = end & !(step - 1);

    let capacity = ((last_subnet_start - first_subnet_start) / step + 1) as usize;
    let mut subnets = Vec::with_capacity(capacity);

    for current in (first_subnet_start..=last_subnet_start).step_by(step as usize) {
        let addr = Ipv4Addr::from(current);
        let subnet = Ipv4Network::new(addr, 24)
            .context("Failed to create subnet")?;
        subnets.push(subnet);
    }

    Ok(subnets)
}

fn probe_host(
    ip: IpAddr,
    attempts: u8,
    socket_type: &ConfigSocketType,
    ping_type: &Vec<ConfigPingType>,
    tcp_ports: &[u16],
    tcp_sni_host: Option<&str>,
    network_interface: Option<&str>,
) -> HostProbeResult {
    let socket = match socket_type {
        ConfigSocketType::DGRAM => ping::DGRAM,
        ConfigSocketType::RAW => ping::RAW,
    };

    let mut result = HostProbeResult::default();

    if ping_type.contains(&ConfigPingType::ICMP) {
        for _ in 0..attempts {
            let mut ping = Ping::new(ip);
            ping.timeout(Duration::from_secs(1)).socket_type(socket);
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if let Some(network_interface) = network_interface {
                ping.bind_device(network_interface);
            }

            match ping.send() {
                Ok(_) => {
                    result.icmp = true;
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }

    if ping_type.contains(&ConfigPingType::TCP) {
        let ports = tcp_ports_with_443(tcp_ports);
        for _ in 0..attempts {
            for port in &ports {
                let (status, _) = crate::tcp_ping::probe_tcp_with_optional_sni(
                    ip,
                    *port,
                    tcp_sni_host,
                    network_interface,
                    Duration::from_secs(2),
                );
                if status.is_alive() {
                    if !result.tcp_ports.contains(port) {
                        result.tcp_ports.push(*port);
                    }
                    if status == TcpProbeStatus::Rejected && !result.tcp_rejected_ports.contains(port) {
                        result.tcp_rejected_ports.push(*port);
                    }
                }
            }
            if result.tcp_alive() {
                break;
            }
        }
    }

    result
}

fn ping_host_icmp_only(
    ip: IpAddr,
    attempts: u8,
    socket_type: &ConfigSocketType,
    network_interface: Option<&str>,
) -> bool {
    probe_host(
        ip,
        attempts,
        socket_type,
        &vec![ConfigPingType::ICMP],
        &[],
        None,
        network_interface,
    )
    .icmp
}

fn ping_endpoint(
    endpoint: &String,
    attempts: u8,
    socket_type: &ConfigSocketType,
    network_interface: Option<&str>,
) -> bool {

    let ip: IpAddr = if endpoint.parse::<Ipv4Addr>().is_err() {
        let endpoint_host: String = if !endpoint.contains(":") {
            format!("{}:{}", endpoint, 80)
        } else {
            endpoint.clone()
        };
        let addrs: Vec<_> = match endpoint_host.to_socket_addrs() {
            Ok(addrs) => addrs.collect(),
            Err(_) => vec![],
        };
        if addrs.is_empty() {
            return false
        } else {
            addrs[0].ip()
        }
    } else {
        endpoint.parse().unwrap()
    };

    ping_host_icmp_only(ip, attempts, socket_type, network_interface)
}

fn resolve_stop_target_with_timeout(
    target: &str,
    port: u16,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
) -> anyhow::Result<IpAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    let lookup = if target.contains(':') {
        target.to_string()
    } else {
        format!("{target}:{port}")
    };

    let target_label = target.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let result = lookup
            .to_socket_addrs()
            .with_context(|| format!("Failed to resolve stop_on_available target {target_label}"))
            .and_then(|addrs| {
                addrs
                    .map(|addr| addr.ip())
                    .next()
                    .context(format!("No addresses resolved for stop_on_available target {target_label}"))
            });
        let _ = tx.send(result);
    });

    let started = Instant::now();
    loop {
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            anyhow::bail!("whitelist probe cancelled");
        }
        if started.elapsed() >= timeout {
            anyhow::bail!("DNS timeout for stop_on_available target {target}");
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("DNS resolver thread exited unexpectedly for {target}");
            }
        }
    }
}

struct StopTargetChecker {
    stop: StopOnAvailableConfig,
    resolved_ip: Option<IpAddr>,
    resolve_error_logged: bool,
}

impl StopTargetChecker {
    fn new(stop: StopOnAvailableConfig) -> Self {
        Self {
            stop,
            resolved_ip: None,
            resolve_error_logged: false,
        }
    }

    fn label(&self) -> String {
        stop_on_available_label(&self.stop)
    }

    fn is_available(
        &mut self,
        network_interface: Option<&str>,
        cancel: Option<&AtomicBool>,
    ) -> (bool, Option<String>) {
        if self.resolved_ip.is_none() {
            match resolve_stop_target_with_timeout(
                &self.stop.target,
                self.stop.port,
                Duration::from_secs(2),
                cancel,
            ) {
                Ok(ip) => self.resolved_ip = Some(ip),
                Err(error) => {
                    if !self.resolve_error_logged {
                        self.resolve_error_logged = true;
                        let msg = format!(
                            "whitelist probe: cannot resolve {} ({error})",
                            self.stop.target
                        );
                        return (false, Some(msg));
                    }
                    return (false, None);
                }
            }
        }

        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return (false, Some("whitelist probe cancelled".to_string()));
        }

        let ip = self.resolved_ip.expect("resolved above");
        let (status, _) = crate::tcp_ping::probe_tcp_with_optional_sni(
            ip,
            self.stop.port,
            None,
            network_interface,
            Duration::from_millis(800),
        );
        (status.is_alive(), None)
    }
}

fn stop_on_available_label(stop: &StopOnAvailableConfig) -> String {
    if stop.target.contains(':') {
        stop.target.clone()
    } else {
        format!("{}:{}", stop.target, stop.port)
    }
}

fn whitelist_info(config: &Config) -> WhitelistInfo {
    match &config.stop_on_available {
        Some(stop) if stop.is_active() => WhitelistInfo {
            label: stop_on_available_label(stop),
            enabled: true,
            check_before: stop.check_before_subnet,
            check_after: stop.check_after_subnet,
        },
        Some(stop) if stop.enabled => WhitelistInfo {
            label: "target пуст".to_string(),
            enabled: false,
            check_before: stop.check_before_subnet,
            check_after: stop.check_after_subnet,
        },
        _ => WhitelistInfo::off(),
    }
}

fn count_rejected_hosts(stats: &SubnetProbeStats) -> usize {
    stats
        .hosts
        .iter()
        .filter(|host| !host.tcp_rejected_ports.is_empty())
        .count()
}

fn ping_types_label(ping_type: &[ConfigPingType]) -> Vec<String> {
    ping_type
        .iter()
        .map(|p| match p {
            ConfigPingType::ICMP => "ICMP".to_string(),
            ConfigPingType::TCP => "TCP".to_string(),
        })
        .collect()
}

fn graceful_stop_on_available(
    state_path: &Path,
    state: &mut ScanState,
    stop: &StopOnAvailableConfig,
    subnet: Option<&str>,
    ui: Option<&ScanUi>,
) -> anyhow::Result<()> {
    let label = stop_on_available_label(stop);
    state.stopped_reason = Some(format!("stop_on_available:{label}"));
    state.finished = false;
    save_state(state_path, state)?;

    let msg = match subnet {
        Some(subnet) => format!("whitelist stop: {label} available, discarded {subnet}"),
        None => format!("whitelist stop: {label} available"),
    };

    if let Some(ui) = ui {
        ui.log(EventLevel::Wrn, msg);
        ui.set_whitelist_status("доступен — стоп");
    } else {
        println!("{}", msg.bright_yellow());
    }

    Ok(())
}

async fn process_subnet(
    subnet: Ipv4Network,
    geoip: Option<&GeoIpService>,
    source: &str,
    fallback_country: Option<&str>,
    socket_type: &ConfigSocketType,
    ping_type: &Vec<ConfigPingType>,
    tcp_ports: &[u16],
    tcp_sni_host: Option<&str>,
    network_interface: Option<&str>,
) -> anyhow::Result<(Ipv4Network, SubnetInfo, SubnetProbeStats)> {
    // Получаем GeoIP информацию для первого IP подсети
    let first_ip = subnet.network();
    let mut geoip_info = match geoip {
        Some(geoip) => geoip.get_ip_info(IpAddr::V4(first_ip))?,
        None => SubnetInfo::with_source(source),
    };
    geoip_info.source = source.to_string();
    if geoip_info.country == "N/A" {
        if let Some(country) = fallback_country {
            geoip_info.country = country.to_string();
        }
    }

    let hosts: Vec<IpAddr> = subnet.iter()
        .filter(|addr| addr.octets()[3] > 0 && addr.octets()[3] < 255)
        .map(|addr| addr.to_string().parse().unwrap())
        .collect();

    // Параллельно проверяем все хосты в подсети
    let host_results: Vec<HostProbeRecord> = hosts
        .par_iter()
        .map(|&ip| {
            let probe = probe_host(ip, 2, socket_type, ping_type, tcp_ports, tcp_sni_host, network_interface);
            let octet = match ip {
                IpAddr::V4(ip) => ip.octets()[3],
                IpAddr::V6(_) => 0,
            };
            HostProbeRecord {
                octet,
                icmp: probe.icmp,
                tcp_ports: probe.tcp_ports.clone(),
                tcp_rejected_ports: probe.tcp_rejected_ports.clone(),
                tcp_alive: probe.tcp_alive(),
            }
        })
        .collect();

    let mut tcp_port_alive = BTreeMap::new();
    let mut tcp_port_rejected = BTreeMap::new();
    for port in tcp_ports_with_443(tcp_ports) {
        tcp_port_alive.insert(port, 0);
        tcp_port_rejected.insert(port, 0);
    }
    for host in &host_results {
        for port in &host.tcp_ports {
            *tcp_port_alive.entry(*port).or_insert(0) += 1;
        }
        for port in &host.tcp_rejected_ports {
            *tcp_port_rejected.entry(*port).or_insert(0) += 1;
        }
    }

    let stats = SubnetProbeStats {
        icmp_alive: host_results.iter().filter(|host| host.icmp).count(),
        tcp_alive: host_results.iter().filter(|host| host.tcp_alive).count(),
        tcp_port_alive,
        tcp_port_rejected,
        hosts: host_results,
    };

    Ok((subnet, geoip_info, stats))
}

fn wait_for_any_key() -> std::io::Result<()> {
    use std::io::Read;

    println!("PAUSED...press enter");
    let _ = std::io::stdin().bytes().next();
    Ok(())
}

pub struct SubnetScanFile {
    pub file_name: String,
    pub file_path: String,
}

pub async fn app(config: &Config, task: SubnetScanFile) -> anyhow::Result<()> {
    let subnets = if task.file_name.is_empty() {
        config.subnets.clone()
    } else {
        let mut file = File::open(&task.file_path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<String>>()
    };

    let scan_name = if task.file_name.is_empty() {
        "ping_result".to_string()
    } else {
        task.file_name
    };

    scan_networks(config, &scan_name, subnets).await
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanState {
    version: u8,
    job_id: String,
    scan_name: String,
    result_csv: String,
    result_jsonl: String,
    #[serde(default)]
    result_alive_txt: String,
    #[serde(default)]
    result_rejected_txt: String,
    completed_subnets: Vec<String>,
    failed_subnets: Vec<String>,
    subnet24_count: u32,
    created_at: String,
    updated_at: String,
    finished: bool,
    #[serde(default)]
    stopped_reason: Option<String>,
}

fn timestamp() -> String {
    chrono::Local::now().format("%Y%m%d_%H%M%S").to_string()
}

fn operator_part(config: &Config) -> String {
    config
        .operator
        .as_deref()
        .filter(|operator| !operator.is_empty())
        .map(|operator| format!("_{operator}_"))
        .unwrap_or_else(|| "_".to_string())
}

fn update_hash(hash: &mut u64, value: &str) {
    for byte in value.as_bytes() {
        *hash ^= *byte as u64;
        *hash = hash.wrapping_mul(0x100000001b3);
    }
}

fn build_job_id(config: &Config, scan_name: &str, networks: &[String]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    update_hash(&mut hash, "result_schema_tcp_txt_lists_v1");
    update_hash(&mut hash, scan_name);
    update_hash(&mut hash, &format!("{:?}", config.ping_type));
    update_hash(&mut hash, &format!("{:?}", config.tcp_ports()));
    update_hash(&mut hash, config.tcp_sni_host.as_deref().unwrap_or(""));
    update_hash(&mut hash, config.operator.as_deref().unwrap_or(""));
    for network in networks {
        update_hash(&mut hash, network);
    }
    format!("{hash:016x}")
}

fn state_path(config: &Config, job_id: &str) -> PathBuf {
    Path::new(config.resume_state_dir()).join(format!("{job_id}.json"))
}

fn load_state(path: &Path) -> anyhow::Result<Option<ScanState>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(path)?;
    let state = serde_json::from_str(&content)?;
    Ok(Some(state))
}

fn save_state(path: &Path, state: &mut ScanState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    state.updated_at = chrono::Local::now().to_rfc3339();
    fs::write(path, serde_json::to_string_pretty(state)?)?;
    Ok(())
}

fn create_state(config: &Config, scan_name: &str, job_id: String) -> ScanState {
    let result_path = PathBuf::from(config.results_dir());
    let date_string = timestamp();
    let filename = format!("{scan_name}{}{date_string}", operator_part(config));
    let result_csv = result_path.join(format!("{filename}.csv")).to_string_lossy().to_string();
    let result_jsonl = result_path.join(format!("{filename}.jsonl")).to_string_lossy().to_string();
    let result_alive_txt = result_path.join(format!("{filename}_alive.txt")).to_string_lossy().to_string();
    let result_rejected_txt = result_path.join(format!("{filename}_rejected.txt")).to_string_lossy().to_string();
    let now = chrono::Local::now().to_rfc3339();

    ScanState {
        version: 1,
        job_id,
        scan_name: scan_name.to_string(),
        result_csv,
        result_jsonl,
        result_alive_txt,
        result_rejected_txt,
        completed_subnets: Vec::new(),
        failed_subnets: Vec::new(),
        subnet24_count: 1,
        created_at: now.clone(),
        updated_at: now,
        finished: false,
        stopped_reason: None,
    }
}

fn expand_to_24(networks: &[String]) -> anyhow::Result<Vec<Ipv4Network>> {
    let mut seen = HashSet::new();
    let mut expanded = Vec::new();

    for network in networks {
        let ip_net: Ipv4Network = network
            .parse()
            .with_context(|| format!("Failed to parse network {}", network))?;
        for subnet in split_ipv4_to_24(ip_net)? {
            let key = (u32::from(subnet.network()), subnet.prefix());
            if seen.insert(key) {
                expanded.push(subnet);
            }
        }
    }

    expanded.sort_by_key(|network| (u32::from(network.network()), network.prefix()));
    Ok(expanded)
}

fn scan_source(scan_name: &str) -> String {
    scan_name
        .strip_prefix("geoip_")
        .unwrap_or(scan_name)
        .replace('_', ",")
        .to_uppercase()
}

fn fallback_country_for_source(source: &str) -> Option<String> {
    if source.len() == 2 && source.chars().all(|ch| ch.is_ascii_alphabetic()) {
        Some(source.to_string())
    } else {
        None
    }
}

pub async fn scan_networks(
    config: &Config,
    scan_name: &str,
    networks: Vec<String>,
) -> anyhow::Result<()> {

    let geoip = match GeoIpService::new(
        &config.geoip_city_db.as_ref().unwrap(),
        &config.geoip_asn_db.as_ref().unwrap(),
    ) {
        Ok(geoip) => Some(geoip),
        Err(e) => {
            eprintln!("⚠️ GeoIP mmdb unavailable, scan results will use N/A geo fields: {}", e);
            None
        }
    };

    if config.ping_type.contains(&ConfigPingType::ICMP) {
        let socket_type = config
            .socket_type
            .as_ref()
            .context("socket_type is required when ICMP is enabled")?;
        if !probe_host(
            "127.0.0.1".parse()?,
            1,
            socket_type,
            &vec![ConfigPingType::ICMP],
            &[],
            None,
            None,
        )
        .icmp
        {
            let hint = match socket_type {
                ConfigSocketType::DGRAM => {
                    "On Linux allow unprivileged ICMP:\n  sudo sysctl -w net.ipv4.ping_group_range=\"0 1000\"\nSee README section «Локальная сборка → Для ICMP без sudo».\nOr set socket_type = \"RAW\" with CAP_NET_RAW/sudo, or ping_type = [\"TCP\"]."
                }
                ConfigSocketType::RAW => {
                    "RAW ICMP needs CAP_NET_RAW or root.\nSee README section «Локальная сборка».\nOr set ping_type = [\"TCP\"]."
                }
            };
            anyhow::bail!("PING ({socket_type:?}) not available.\n{hint}");
        }
    }

    let mut processed_networks: Vec<(Ipv4Network, SubnetInfo, SubnetProbeStats)> = Vec::new();
    let endpoint = config.endpoint.clone();
    let tcp_ports = config.tcp_ports();
    let tcp_sni_host = config.tcp_sni_host.as_deref();
    let network_interface = config.network_interface();
    let source = scan_source(scan_name);
    let fallback_country = fallback_country_for_source(&source);
    let all_subnets = expand_to_24(&networks)?;
    let job_id = build_job_id(config, scan_name, &networks);
    let state_path = state_path(config, &job_id);
    let mut state = match (config.resume_enabled(), load_state(&state_path)?) {
        (true, Some(state)) if !state.finished => state,
        _ => create_state(config, scan_name, job_id),
    };
    save_state(&state_path, &mut state)?;

    let mut completed_subnets: HashSet<String> = state.completed_subnets.iter().cloned().collect();
    let mut failed_subnets: HashSet<String> = state.failed_subnets.iter().cloned().collect();
    let is_task = config.task.is_some();
    let stop_every = if is_task {
        config.task.as_ref().unwrap().stop_every_times
    } else {
        0
    };
    let mut stop_checker = config
        .stop_on_available
        .as_ref()
        .filter(|stop| stop.is_active())
        .cloned()
        .map(StopTargetChecker::new);

    let whitelist_label = stop_checker.as_ref().map(|c| c.label());
    let use_tui = config.use_tui();
    let socket_type = config
        .socket_type
        .as_ref()
        .context("socket_type is required")?;
    let mut ui: Option<ScanUi> = if use_tui {
        let ui_config = ScanUiConfig {
            scan_name: scan_name.to_string(),
            total_subnets: all_subnets.len(),
            resume_count: completed_subnets.len(),
            endpoint: endpoint.clone(),
            whitelist: whitelist_info(config),
            tcp_ports: tcp_ports.clone(),
            socket_type: format!("{socket_type:?}"),
            ping_types: ping_types_label(&config.ping_type),
            result_jsonl: state.result_jsonl.clone(),
            last_stop: state.stopped_reason.clone(),
        };
        match ScanUi::try_start(ui_config) {
            Ok(ui) => Some(ui),
            Err(e) => {
                eprintln!("TUI unavailable ({e}), falling back to plain output");
                None
            }
        }
    } else {
        None
    };

    if ui.is_none() {
        let mut scan_meta = vec![
            format!("{scan_name}"),
            format!("{} /24", all_subnets.len()),
        ];
        if !completed_subnets.is_empty() {
            scan_meta.push(format!("resume {}", completed_subnets.len()));
        }
        if let Some(label) = &whitelist_label {
            scan_meta.push(format!("whitelist {label}"));
        } else {
            let wl = whitelist_info(config);
            if !wl.enabled {
                scan_meta.push("whitelist выкл".to_string());
            }
        }
        scan_meta.push(format!("endpoint {endpoint}"));
        println!("{}", scan_meta.join(" · ").cyan());

        if let Some(reason) = &state.stopped_reason {
            println!("{}", format!("last stop: {reason}").dimmed());
        }
    }

    let mut scanned_this_run = 0usize;
    let mut interrupted = false;
    let scan_progress = ScanProgress::new(ui.is_none(), all_subnets.len(), completed_subnets.len());

    for (index, subnet24) in all_subnets.iter().enumerate() {
        if ui.as_ref().is_some_and(|u| u.cancelled()) {
            interrupted = true;
            break;
        }

        let subnet_string = subnet24.to_string();
        let _string_part = format!("{}/{}", index + 1, all_subnets.len());

        if completed_subnets.contains(&subnet_string) {
            continue;
        }

        if let Some(checker) = &mut stop_checker {
            if ui.as_ref().is_some_and(|u| u.cancelled()) {
                interrupted = true;
                break;
            }
            if let Some(ui) = &ui {
                ui.set_whitelist_status("проверка…");
                ui.log(EventLevel::Inf, format!("Whitelist probe {}", checker.label()));
            }
            let cancel = ui.as_ref().map(|u| u.cancel_flag());
            let (available, warn) = checker.is_available(network_interface, cancel);
            if let Some(warn) = &warn {
                if warn.contains("cancelled") {
                    interrupted = true;
                    break;
                }
                if let Some(ui) = &ui {
                    ui.log(EventLevel::Wrn, warn.clone());
                } else {
                    eprintln!("{}", warn.yellow());
                }
            }
            if checker.stop.check_before_subnet && available {
                graceful_stop_on_available(&state_path, &mut state, &checker.stop, None, ui.as_ref())?;
                if let Some(ui) = ui.take() {
                    ui.finish(format!(
                        "stopped: whitelist · {} /24 this run",
                        scanned_this_run
                    ));
                }
                return Ok(());
            }
            if let Some(ui) = &ui {
                ui.set_whitelist_status(if available { "доступен" } else { "недоступен" });
            }
        }

        let done_before = completed_subnets.len() + scanned_this_run;
        if let Some(ui) = &ui {
            ui.set_scanning(index + 1, &subnet_string);
        } else {
            scan_progress.set_position(done_before, &subnet_string);
        }

        let iteration_start = Instant::now();
        match process_subnet(
            *subnet24,
            geoip.as_ref(),
            &source,
            fallback_country.as_deref(),
            config.socket_type.as_ref().unwrap(),
            &config.ping_type,
            &tcp_ports,
            tcp_sni_host,
            network_interface,
        ).await {
            Ok(result) => {
                let iteration_time = iteration_start.elapsed();
                let stats = &result.2;
                let elapsed_sec = iteration_time.as_secs_f64();
                let rejected = count_rejected_hosts(stats);

                if let Some(checker) = &mut stop_checker {
                    if ui.as_ref().is_some_and(|u| u.cancelled()) {
                        interrupted = true;
                        break;
                    }
                    if let Some(ui) = &ui {
                        ui.set_whitelist_status("проверка…");
                    }
                    let cancel = ui.as_ref().map(|u| u.cancel_flag());
                    let (available, warn) = checker.is_available(network_interface, cancel);
                    if let Some(warn) = &warn {
                        if warn.contains("cancelled") {
                            interrupted = true;
                            break;
                        }
                        if let Some(ui) = &ui {
                            ui.log(EventLevel::Wrn, warn.clone());
                        } else {
                            eprintln!("{}", warn.yellow());
                        }
                    }
                    if checker.stop.check_after_subnet && available {
                        graceful_stop_on_available(
                            &state_path,
                            &mut state,
                            &checker.stop,
                            Some(&subnet_string),
                            ui.as_ref(),
                        )?;
                        if let Some(ui) = ui.take() {
                            ui.finish(format!(
                                "stopped: whitelist · {} /24 this run",
                                scanned_this_run
                            ));
                        }
                        return Ok(());
                    }
                    if let Some(ui) = &ui {
                        ui.set_whitelist_status(if available { "доступен" } else { "недоступен" });
                    }
                }

                if let Some(ui) = &ui {
                    ui.complete_subnet(
                        index + 1,
                        &subnet_string,
                        stats.icmp_alive,
                        stats.tcp_alive,
                        rejected,
                        elapsed_sec,
                    );
                } else if scan_progress.is_active() {
                    let summary = if stats.tcp_alive > 0 || stats.icmp_alive > 0 {
                        format!(
                            "{} icmp {} tcp {} {:.1}s",
                            subnet_string, stats.icmp_alive, stats.tcp_alive, elapsed_sec
                        )
                    } else {
                        format!("{subnet_string} dead {elapsed_sec:.1}s")
                    };
                    scan_progress.set_message(summary);
                }

                append_result_to_csv(&result, &state.result_csv)?;
                append_result_to_jsonl(&result, &state.result_jsonl)?;
                append_result_to_txt_lists(&result, &state.result_alive_txt, &state.result_rejected_txt)?;
                processed_networks.push(result);
                completed_subnets.insert(subnet_string.clone());
                failed_subnets.remove(&subnet_string);
                scanned_this_run += 1;
                scan_progress.complete_subnet();
            }
            Err(e) => {
                if let Some(ui) = &ui {
                    ui.subnet_error(index + 1, &subnet_string, &e.to_string());
                } else {
                    eprintln!("{}", format!("  error {subnet_string}: {e}").red());
                }
                failed_subnets.insert(subnet_string.clone());
            }
        }

        state.completed_subnets = completed_subnets.iter().cloned().collect();
        state.failed_subnets = failed_subnets.iter().cloned().collect();
        state.subnet24_count += 1;
        save_state(&state_path, &mut state)?;

        let mut endpoint_available = false;
        let max_loop: u32 = 6;
        for cnt in 0..max_loop {
            if ping_endpoint(&endpoint, 1, config.socket_type.as_ref().unwrap(), network_interface) {
                endpoint_available = true;
                break;
            }

            if cnt + 1 < max_loop {
                let delay = if cnt < 4 { 5000 + cnt * 5000 } else { 60000 };
                let retry_msg = format!(
                    "Endpoint [{endpoint}] unavailable, retry {}/{} in {}s",
                    cnt + 1,
                    max_loop,
                    delay / 1000
                );
                if let Some(ui) = &ui {
                    ui.log(EventLevel::Wrn, retry_msg);
                    ui.set_endpoint_ok(false);
                } else {
                    eprintln!("⚠️ {retry_msg}");
                }
                tokio::time::sleep(Duration::from_millis(delay as u64)).await;
            }
        }

        if let Some(ui) = &ui {
            ui.set_endpoint_ok(endpoint_available);
        }

        if !endpoint_available {
            match config.endpoint_failure_action() {
                ConfigEndpointFailureAction::Stop => {
                    let msg = format!("Endpoint [{endpoint}] unavailable, stopping");
                    if let Some(ui) = ui.take() {
                        ui.log(EventLevel::Err, msg.clone());
                        save_state(&state_path, &mut state)?;
                        ui.finish(format!("error: {msg}"));
                    } else {
                        eprintln!("❌ {msg}");
                        save_state(&state_path, &mut state)?;
                    }
                    return Err(anyhow::Error::msg("Endpoint unavailable"));
                }
                ConfigEndpointFailureAction::ChangeIp => {
                    let task = config
                        .task
                        .as_ref()
                        .context("task config is required for endpoint_failure_action = ChangeIp")?;
                    let change_ip_url = task
                        .change_ip_url
                        .as_ref()
                        .context("task.change_ip_url is required for endpoint_failure_action = ChangeIp")?;
                    let rotate_msg = format!("Endpoint [{endpoint}] unavailable, requesting IP rotation");
                    if let Some(ui) = &ui {
                        ui.log(EventLevel::Wrn, rotate_msg);
                    } else {
                        eprintln!("⚠️ {rotate_msg}");
                    }
                    crate::utils::change_ip(change_ip_url).await?;
                    let delay_seconds = task.delay_seconds.unwrap_or(5);
                    sleep(Duration::from_secs(delay_seconds)).await;

                    if !ping_endpoint(&endpoint, 1, config.socket_type.as_ref().unwrap(), network_interface) {
                        let msg = format!("Endpoint [{endpoint}] still unavailable after IP rotation, stopping");
                        if let Some(ui) = ui.take() {
                            ui.log(EventLevel::Err, msg.clone());
                            save_state(&state_path, &mut state)?;
                            ui.finish(format!("error: {msg}"));
                        } else {
                            eprintln!("❌ {msg}");
                            save_state(&state_path, &mut state)?;
                        }
                        return Err(anyhow::Error::msg("Endpoint unavailable after IP rotation"));
                    }
                }
            }
        }

        if stop_every != 0 && state.subnet24_count % stop_every == 0 {
            if let Some(task) = &config.task {
                match &task.stop_action {
                    ConfigStopAction::Delay => {
                        let delay_seconds = task.delay_seconds.unwrap();
                        let msg = format!("PAUSED...delay {delay_seconds} sec");
                        if let Some(ui) = &ui {
                            ui.log(EventLevel::Inf, msg);
                        } else {
                            println!("{msg}");
                        }
                        sleep(Duration::from_secs(delay_seconds)).await;
                    },
                    ConfigStopAction::ChangeIp => {
                        let change_ip_url = task.change_ip_url.as_ref().unwrap();
                        if let Some(ui) = &ui {
                            ui.log(EventLevel::Inf, "PAUSED...change IP");
                        }
                        crate::utils::change_ip(change_ip_url).await?;
                    },
                    ConfigStopAction::Prompt => {
                        if ui.is_some() {
                            if let Some(ui) = &ui {
                                ui.log(EventLevel::Wrn, "Prompt pause: switch console to plain mode for wait_for_any_key");
                            }
                        }
                        wait_for_any_key()?;
                    },
                }
            }
        }
    }

    if interrupted {
        save_state(&state_path, &mut state)?;
        let msg = format!(
            "interrupted: {} /24 this run, {} total · resume: {}",
            scanned_this_run,
            completed_subnets.len(),
            state.result_jsonl
        );
        if let Some(ui) = ui.take() {
            ui.log(EventLevel::Wrn, "Остановлено пользователем");
            ui.finish(msg);
        } else {
            println!("{}", msg.yellow());
        }
        return Ok(());
    }

    state.finished = true;
    state.stopped_reason = None;
    save_state(&state_path, &mut state)?;

    let done_msg = format!(
        "done: {} /24 this run, {} total · {}",
        scanned_this_run,
        completed_subnets.len(),
        state.result_jsonl
    );

    if let Some(ui) = ui {
        ui.log(EventLevel::Ok, "Скан завершён");
        ui.finish(done_msg);
    } else {
        println!("{}", done_msg.cyan());
    }

    if config.logger_filetype.len() > 0 {
        let result_path = PathBuf::from(config.results_dir());

        if config.logger_filetype.contains(&ConfigSaveResultFileType::Csv) {
            let csv = result_path.join(format!("{}_final.csv", state.job_id));
            let csv = csv.to_string_lossy().to_string();
            let _ = save_results_to_file(&processed_networks.clone(), &csv.as_str());
        }
        if config.logger_filetype.contains(&ConfigSaveResultFileType::Json) {
            let json = result_path.join(format!("{}_final.json", state.job_id));
            let json = json.to_string_lossy().to_string();
            let _ = save_results_to_json(&processed_networks.clone(), &json.as_str());
        }
    }
    Ok(())
}

struct ScanProgress(Option<ProgressBar>);

impl ScanProgress {
    fn new(enabled: bool, total: usize, resume_done: usize) -> Self {
        if !enabled || total == 0 {
            return Self(None);
        }
        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::with_template(
                " [{bar:50.cyan/blue}] {pos}/{len} ({percent_precise}%) eta {eta} {msg}",
            )
            .unwrap()
            .progress_chars("█▓░"),
        );
        pb.set_position(resume_done as u64);
        Self(Some(pb))
    }

    fn is_active(&self) -> bool {
        self.0.is_some()
    }

    fn set_position(&self, done: usize, subnet: &str) {
        if let Some(pb) = &self.0 {
            pb.set_position(done as u64);
            pb.set_message(subnet.to_string());
        }
    }

    fn set_message(&self, message: impl Into<String>) {
        if let Some(pb) = &self.0 {
            pb.set_message(message.into());
        }
    }

    fn complete_subnet(&self) {
        if let Some(pb) = &self.0 {
            pb.inc(1);
        }
    }
}

impl Drop for ScanProgress {
    fn drop(&mut self) {
        if let Some(pb) = self.0.take() {
            pb.finish_and_clear();
        }
    }
}