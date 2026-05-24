use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Write, BufWriter};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use ipnetwork::Ipv4Network;
use regex::Regex;
use reqwest::Client;
use serde::Serialize;
use anyhow::Context;
use crate::geoip::SubnetInfo;

#[derive(Clone, Debug)]
pub struct HostProbeRecord {
    pub octet: u8,
    pub icmp: bool,
    pub tcp_ports: Vec<u16>,
    pub tcp_alive: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SubnetProbeStats {
    pub icmp_alive: usize,
    pub tcp_alive: usize,
    pub tcp_port_alive: BTreeMap<u16, usize>,
    pub hosts: Vec<HostProbeRecord>,
}

#[derive(Serialize)]
struct CompactProbeRecord {
    format: &'static str,
    icmp: Vec<String>,
    tcp_ports: BTreeMap<u16, Vec<String>>,
    dead: Vec<String>,
}

impl CompactProbeRecord {
    fn from_stats(stats: &SubnetProbeStats) -> Self {
        let mut tcp_ports = BTreeMap::new();
        for port in stats.tcp_port_alive.keys() {
            tcp_ports.insert(
                *port,
                ranges_from_octets(
                    stats
                        .hosts
                        .iter()
                        .filter(|host| host.tcp_ports.contains(port))
                        .map(|host| host.octet),
                ),
            );
        }

        Self {
            format: "last_octet_ranges",
            icmp: ranges_from_octets(stats.hosts.iter().filter(|host| host.icmp).map(|host| host.octet)),
            tcp_ports,
            dead: ranges_from_octets(stats.hosts.iter().filter(|host| !host.icmp && !host.tcp_alive).map(|host| host.octet)),
        }
    }
}

fn ranges_from_octets(octets: impl Iterator<Item = u8>) -> Vec<String> {
    let mut octets: Vec<u8> = octets.collect();
    octets.sort_unstable();
    octets.dedup();

    let mut ranges = Vec::new();
    let Some(mut start) = octets.first().copied() else {
        return ranges;
    };
    let mut end = start;

    for octet in octets.into_iter().skip(1) {
        if octet == end.saturating_add(1) {
            end = octet;
            continue;
        }
        push_range(&mut ranges, start, end);
        start = octet;
        end = octet;
    }
    push_range(&mut ranges, start, end);

    ranges
}

pub fn tcp_port_summary(stats: &SubnetProbeStats) -> String {
    stats
        .tcp_port_alive
        .iter()
        .map(|(port, count)| format!("{port}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn tcp_port_columns(results: &[(Ipv4Network, SubnetInfo, SubnetProbeStats)]) -> Vec<u16> {
    let mut ports = BTreeMap::new();
    for (_, _, stats) in results {
        for port in stats.tcp_port_alive.keys() {
            ports.insert(*port, ());
        }
    }
    ports.keys().copied().collect()
}

fn tcp_port_header(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|port| format!("tcp_{port}_hosts"))
        .collect::<Vec<_>>()
        .join(";")
}

fn tcp_port_values(stats: &SubnetProbeStats, ports: &[u16]) -> String {
    ports
        .iter()
        .map(|port| stats.tcp_port_alive.get(port).copied().unwrap_or(0).to_string())
        .collect::<Vec<_>>()
        .join(";")
}

fn push_range(ranges: &mut Vec<String>, start: u8, end: u8) {
    if start == end {
        ranges.push(start.to_string());
    } else {
        ranges.push(format!("{start}-{end}"));
    }
}

#[derive(Serialize)]
pub struct SubnetRecord {
    subnet: String,
    source: String,
    country: String,
    city: String,
    asn: u32,
    as_name: String,
    icmp_hosts: usize,
    active_hosts: usize,
    tcp_ports: BTreeMap<u16, usize>,
    probe: CompactProbeRecord,
}

impl SubnetRecord {
    pub fn from_result(result: &(Ipv4Network, SubnetInfo, SubnetProbeStats)) -> Self {
        let (subnet, info, stats) = result;
        Self {
            subnet: subnet.to_string(),
            source: info.source.clone(),
            country: info.country.clone(),
            city: info.city.clone(),
            asn: info.asn,
            as_name: info.as_name.clone(),
            icmp_hosts: stats.icmp_alive,
            active_hosts: stats.tcp_alive,
            tcp_ports: stats.tcp_port_alive.clone(),
            probe: CompactProbeRecord::from_stats(stats),
        }
    }
}

pub fn save_results_to_file(
    results: &[(Ipv4Network, SubnetInfo, SubnetProbeStats)],
    filename: &str,
) -> anyhow::Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = Path::new(filename).parent() {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(filename)?;
    let mut writer = BufWriter::new(file);
    let tcp_ports = tcp_port_columns(results);
    let tcp_header = tcp_port_header(&tcp_ports);

    writeln!(
        writer,
        "subnet;source;country;city;asn;as_name;icmp_hosts;active_hosts{}{}",
        if tcp_header.is_empty() { "" } else { ";" },
        tcp_header,
    )?;

    // Записываем данные
    for (subnet, info, stats) in results {
        writeln!(
            writer,
            "{};{};{};{};{};{};{};{}{}{}",
            subnet,
            info.source,
            info.country,
            info.city,
            info.asn,
            info.as_name,
            stats.icmp_alive,
            stats.tcp_alive,
            if tcp_ports.is_empty() { "" } else { ";" },
            tcp_port_values(stats, &tcp_ports),
        )?;
    }

    writer.flush()?;
    println!("CSV saved: {}", filename);

    Ok(())
}

pub fn save_results_to_json(
    results: &[(Ipv4Network, SubnetInfo, SubnetProbeStats)],
    filename: &str,
) -> anyhow::Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = Path::new(filename).parent() {
        fs::create_dir_all(parent)?;
    }

    let records: Vec<SubnetRecord> = results
        .iter()
        .map(SubnetRecord::from_result)
        .collect();

    let json = serde_json::to_string_pretty(&records)?;
    fs::write(filename, json)?;
    println!("JSON saved: {}", filename);

    Ok(())
}

pub fn append_result_to_csv(
    result: &(Ipv4Network, SubnetInfo, SubnetProbeStats),
    filename: &str,
) -> anyhow::Result<()> {
    if let Some(parent) = Path::new(filename).parent() {
        fs::create_dir_all(parent)?;
    }

    let should_write_header = fs::metadata(filename)
        .map(|metadata| metadata.len() == 0)
        .unwrap_or(true);
    let file = OpenOptions::new().create(true).append(true).open(filename)?;
    let mut writer = BufWriter::new(file);
    let tcp_ports: Vec<u16> = result.2.tcp_port_alive.keys().copied().collect();
    let tcp_header = tcp_port_header(&tcp_ports);

    if should_write_header {
        writeln!(
            writer,
            "subnet;source;country;city;asn;as_name;icmp_hosts;active_hosts{}{}",
            if tcp_header.is_empty() { "" } else { ";" },
            tcp_header,
        )?;
    }

    let record = SubnetRecord::from_result(result);
    writeln!(
        writer,
        "{};{};{};{};{};{};{};{}{}{}",
        record.subnet,
        record.source,
        record.country,
        record.city,
        record.asn,
        record.as_name,
        record.icmp_hosts,
        record.active_hosts,
        if tcp_ports.is_empty() { "" } else { ";" },
        tcp_port_values(&result.2, &tcp_ports),
    )?;
    writer.flush()?;

    Ok(())
}

pub fn append_result_to_jsonl(
    result: &(Ipv4Network, SubnetInfo, SubnetProbeStats),
    filename: &str,
) -> anyhow::Result<()> {
    if let Some(parent) = Path::new(filename).parent() {
        fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new().create(true).append(true).open(filename)?;
    let mut writer = BufWriter::new(file);
    let record = SubnetRecord::from_result(result);
    writeln!(writer, "{}", serde_json::to_string(&record)?)?;
    writer.flush()?;

    Ok(())
}

pub async fn change_ip(url: &str) -> anyhow::Result<()> {
    let client = Client::new();

    let response = client
        .get(url)
        .header("User-Agent", "curl/7.88.1")
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .context(format!("Error requesting change IP endpoint {}", url))?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "HTTP error change IP endpoint {}: {}",
            url,
            response.status()
        ));
    }

    println!("Change IP requested: {}", url);
    Ok(())
}

pub async fn get_current_ip() -> anyhow::Result<IpAddr> {
    let client = Client::new();

    let response = client
        .get("https://yandex.ru/internet")
        // .get("https://httpbin.org/headers")
        .header("User-Agent", "curl/7.88.1")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .context("Error fetching yandex.ru/internet")?;

    // println!("Response: {:?}", response);

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "HTTP error yandex.ru/internet: {}",
            response.status()
        ));
    }

    let api_data = response.text().await?;

    // println!("API data: {}", api_data);

    let re = Regex::new(r#""v4":"([^"]*)""#)?;

    if let Some(caps) = re.captures(&api_data) {
        let ip = caps.get(1).unwrap().as_str();
        Ok(ip.parse()?)
    } else {
        Err(anyhow::anyhow!("Error finding IP"))
    }
}