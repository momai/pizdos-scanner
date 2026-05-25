use anyhow::Context;
use ipnetwork::Ipv4Network;
use ping::Ping;
use rayon::prelude::*;
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    time::Duration,
};
use tokio::time::sleep;
use colored::*;
// use futures_util::TryFutureExt;
use crate::init::{
    Config,
    ConfigSocketType,
    ConfigPingType,
};
use crate::geoip::{GeoIpService, SubnetInfo};
use crate::utils::{
    HostProbeRecord,
    SubnetProbeStats,
};
use crate::tcp_ping::TcpProbeStatus;

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

pub(crate) fn split_ipv4_to_24(net: Ipv4Network) -> anyhow::Result<Vec<Ipv4Network>> {
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

pub(crate) fn probe_host(
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

pub(crate) fn ping_endpoint(
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


pub(crate) async fn process_subnet(
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

pub(crate) fn wait_for_any_key() -> std::io::Result<()> {
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
        crate::utils::parse_cidr_lines(&content)
    };

    let scan_name = if task.file_name.is_empty() {
        "ping_result".to_string()
    } else {
        task.file_name
    };

    scan_networks(config, &scan_name, subnets).await
}

pub async fn scan_networks(
    config: &Config,
    scan_name: &str,
    networks: Vec<String>,
) -> anyhow::Result<()> {
    crate::scanner::scan_networks(config, scan_name, networks).await
}
