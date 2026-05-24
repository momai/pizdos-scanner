use anyhow::Context;
use ipnetwork::Ipv4Network;
use ping::Ping;
use rayon::prelude::*;
use std::{
    collections::HashSet,
    fs::{self, File},
    io::Read,
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::{sleep, Instant};
use colored::*;
// use futures_util::TryFutureExt;
use crate::init::{Config, ConfigSocketType, ConfigSaveResultFileType, ConfigPingType};
use crate::geoip::{GeoIpService, SubnetInfo};
use crate::utils::{
    append_result_to_csv,
    append_result_to_jsonl,
    save_results_to_file,
    save_results_to_json,
};
use crate::init::ConfigStopAction;
use serde::{Deserialize, Serialize};

fn log_time() -> String {
    format!("[{}]", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
}

pub async fn ping_subnet_matrix_rayon(
    base_ip: &str,
    attempts: u8,
    socket_type: &ConfigSocketType,
    ping_type: &Vec<ConfigPingType>,
    tcp_ports: &[u16],
    tcp_sni_host: Option<&str>,
) -> anyhow::Result<String> {

    let base_octets: Vec<&str> = base_ip.split('.').collect();
    if base_octets.len() != 4 {
        anyhow::bail!("Wrong IP format");
    }

    if !ping_host("127.0.0.1".parse()?, 1, &socket_type, &vec![ConfigPingType::ICMP], &[], None) {
        anyhow::bail!("PING («{:?}» socket type) not available", &socket_type);
    }

    let a: u8 = base_octets[0].parse().unwrap_or(0);
    let b: u8 = base_octets[1].parse().unwrap_or(0);
    let c: u8 = base_octets[2].parse().unwrap_or(0);

    println!("\n{} {:?} SUBNET {}.{}.{}.0/24:", " ".repeat(20), ping_type, a, b, c);
    println!("{}", "─".repeat(59).cyan());

    // Using rayon for parallel ping
    let results: Vec<(u8, bool)> = (1..=255u8)
        .into_par_iter()
        .map(|i| {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, i));
            let alive = ping_host(ip, attempts, &socket_type, &ping_type, tcp_ports, tcp_sni_host);
            (i, alive)
        })
        .collect();

    let mut first_alive_octet: u8 = 1;
    for (octet, alive) in results.clone() {
        if alive && octet != 1 {
            first_alive_octet = octet;
            break;
        }
    };
    let first_ip = IpAddr::V4(Ipv4Addr::new(a, b, c, first_alive_octet));
    let hostname = dns_lookup::lookup_addr(&first_ip).unwrap_or_else(|_| "None".to_string());

    let columns = 15;
    let mut count = 0;

    for (octet, alive) in results.clone() {
        if alive {
            // print!("{:>3}", "★".green().bold());
            print!("{:<4}", format!("{}", octet).bright_green().bold());
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

    let alive_count = results.iter().filter(|&(_, alive)| *alive).count();
    println!("{}{} of {} available ({:.1}%)",
             " ".repeat(30),
             alive_count.to_string().green(),
             results.len(),
             (alive_count as f32 / results.len() as f32) * 100.0
    );
    println!("{}", "─".repeat(59).cyan());

    println!("PTR for {} - {}", first_ip, hostname);

    let socket = match socket_type {
        ConfigSocketType::DGRAM => ping::DGRAM,
        ConfigSocketType::RAW => ping::RAW,
    };

    let mut pings: Vec<Duration> = vec![];

    for _ in 0..3 {
        match ping::new(first_ip)
            .socket_type(socket)
            .timeout(Duration::from_secs(1))
            // .ttl(128)
            .send()
        {
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

fn ping_host(
    ip: IpAddr,
    attempts: u8,
    socket_type: &ConfigSocketType,
    ping_type: &Vec<ConfigPingType>,
    tcp_ports: &[u16],
    tcp_sni_host: Option<&str>,
) -> bool {

    let socket = match socket_type {
        ConfigSocketType::DGRAM => ping::DGRAM,
        ConfigSocketType::RAW => ping::RAW,
    };

    // ping_type.contains(&ConfigPingType::ICMP)

    let mut res = false;

    for _ in 0..attempts {
        if ping_type.contains(&ConfigPingType::ICMP) {
            match Ping::new(ip).timeout(Duration::from_secs(1)).socket_type(socket).send() {
                Ok(_) => res = true,
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        }

        if ping_type.contains(&ConfigPingType::TCP) && res == false {
            for port in tcp_ports {
                let (ok, _) = crate::tcp_ping::probe_tcp_with_optional_sni(
                    ip,
                    *port,
                    tcp_sni_host,
                    Duration::from_secs(2),
                );
                if ok {
                    println!("TCP {}:{} ok", ip, port);
                    res = true;
                    break;
                }
            }
        }

    }

    // std::thread::sleep(Duration::from_millis(500));

    // false
    res
}

fn ping_endpoint(endpoint: &String, attempts: u8, socket_type: &ConfigSocketType) -> bool {

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

    ping_host(ip, attempts, socket_type, &vec![ConfigPingType::ICMP], &[], None)
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
) -> anyhow::Result<(Ipv4Network, SubnetInfo, usize)> {
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

    // Параллельно пингуем все хосты в подсети
    let successful_hosts: usize = hosts
        .par_iter()
        .map(|&ip| {
            if ping_host(ip, 2, socket_type, ping_type, tcp_ports, tcp_sni_host) {
                1
            } else {
                0
            }
        })
        .sum();

    // if ping_type.contains(&ConfigPingType::TCP) {
    //     sleep(Duration::from_millis(5000)).await
    // }

    Ok((subnet, geoip_info, successful_hosts))
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
    completed_subnets: Vec<String>,
    failed_subnets: Vec<String>,
    subnet24_count: u32,
    created_at: String,
    updated_at: String,
    finished: bool,
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
    let now = chrono::Local::now().to_rfc3339();

    ScanState {
        version: 1,
        job_id,
        scan_name: scan_name.to_string(),
        result_csv,
        result_jsonl,
        completed_subnets: Vec::new(),
        failed_subnets: Vec::new(),
        subnet24_count: 1,
        created_at: now.clone(),
        updated_at: now,
        finished: false,
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

    if !ping_host("127.0.0.1".parse()?, 1, &config.socket_type.as_ref().unwrap(), &vec![ConfigPingType::ICMP], &[], None) {
        anyhow::bail!("PING («{:?}» socket type) not available", &config.socket_type.as_ref().unwrap())
    }

    let mut processed_networks: Vec<(Ipv4Network, SubnetInfo, usize)> = Vec::new();
    let endpoint = config.endpoint.clone();
    let tcp_ports = config.tcp_ports();
    let tcp_sni_host = config.tcp_sni_host.as_deref();
    let source = scan_source(scan_name);
    let fallback_country = fallback_country_for_source(&source);
    let all_subnets = expand_to_24(&networks)?;
    let job_id = build_job_id(config, scan_name, &networks);
    let state_path = state_path(config, &job_id);
    let mut state = match (config.resume_enabled(), load_state(&state_path)?) {
        (true, Some(state)) if !state.finished => {
            println!("Resuming scan state: {}", state_path.display());
            state
        }
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

    println!("STOP EVERY {}, is task {}", stop_every, is_task);
    println!(
        "SCAN {}: {} /24 subnets, state {}",
        scan_name,
        all_subnets.len(),
        state_path.display()
    );

    for (index, subnet24) in all_subnets.iter().enumerate() {
        let subnet_string = subnet24.to_string();
        let string_part = format!("{}/{}", index + 1, all_subnets.len());

        if completed_subnets.contains(&subnet_string) {
            println!("{:<26} {:<7} {:<18} resume-skip", log_time(), string_part, subnet_string);
            continue;
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
        ).await {
            Ok(result) => {
                let iteration_time = iteration_start.elapsed();
                let info_string = if result.2 > 0 { format!("+ {}", result.2) } else { "-".to_string() };

                println!(
                    "{:<26} {:<7} {:<18} {:<5}   [{}ms]",
                    log_time(), string_part, subnet_string, info_string, iteration_time.as_millis()
                );

                append_result_to_csv(&result, &state.result_csv)?;
                append_result_to_jsonl(&result, &state.result_jsonl)?;
                processed_networks.push(result);
                completed_subnets.insert(subnet_string.clone());
                failed_subnets.remove(&subnet_string);
            }
            Err(e) => {
                eprintln!("  Error {}: {}", subnet_string, e);
                failed_subnets.insert(subnet_string.clone());
            }
        }

        state.completed_subnets = completed_subnets.iter().cloned().collect();
        state.failed_subnets = failed_subnets.iter().cloned().collect();
        state.subnet24_count += 1;
        save_state(&state_path, &mut state)?;

        let mut cnt: u32 = 0;
        let max_loop: u32 = 6;
        for _ in 0..max_loop {
            if ping_endpoint(&endpoint, 1, config.socket_type.as_ref().unwrap()) {
                break;
            } else {
                if cnt == 5 {
                    eprintln!("❌  Endpoint [{}] unavailable, stopping", endpoint);
                    save_state(&state_path, &mut state)?;
                    return Err(anyhow::Error::msg("Endpoint unavailable"));
                }
                let delay = if cnt < 4 { 5000 + cnt * 5000 } else { 60000 };
                eprintln!("⚠️ Endpoint [{}] unavailable, retrying [{}sec] {}/{}", endpoint, delay / 1000, cnt + 1, max_loop);
                tokio::time::sleep(Duration::from_millis(delay as u64)).await;
            }
            cnt = cnt + 1;
        }

        if stop_every != 0 && state.subnet24_count % stop_every == 0 {
            if let Some(task) = &config.task {
                match &task.stop_action {
                    ConfigStopAction::Delay => {
                        let delay_seconds = task.delay_seconds.unwrap();
                        println!("PAUSED...delay {} sec", delay_seconds);
                        sleep(Duration::from_secs(delay_seconds)).await;
                    },
                    ConfigStopAction::ChangeIp => {
                        let change_ip_url = task.change_ip_url.as_ref().unwrap();
                        crate::utils::change_ip(change_ip_url).await?;
                    },
                    ConfigStopAction::Prompt => {
                        wait_for_any_key()?;
                    },
                }
            }
        }
    }

    println!("{}", "=".repeat(100));
    println!("{:<16} | {:<5} | {:<12} | {:<3} | {:<15} | {:<10} | {:<30}",
             "subnet", "cnt", "source", "", "geo", "ASN", "ISP");
    println!("{}", "-".repeat(100));
    for (subnet, info, count) in processed_networks.clone() {
        println!("{:<16} | {:<5} | {:<12} | {:<3} | {:<15} | AS{:<8} | {:<30}",
                 subnet.to_string(),
                 count.to_string(),
                 info.source,
                 info.country,
                 info.city,
                 info.asn.to_string(),
                 info.as_name,
        );
    }
    println!("{}", "=".repeat(300));

    state.finished = true;
    save_state(&state_path, &mut state)?;
    println!("CSV journal saved: {}", state.result_csv);
    println!("JSONL journal saved: {}", state.result_jsonl);

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