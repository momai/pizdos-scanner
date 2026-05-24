use std::fs::{self, File, OpenOptions};
use std::io::{Write, BufWriter};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use ipnetwork::Ipv4Network;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use anyhow::Context;
use crate::geoip::SubnetInfo;

#[derive(Serialize, Deserialize)]
pub struct SubnetRecord {
    subnet: String,
    source: String,
    country: String,
    city: String,
    asn: u32,
    as_name: String,
    active_hosts: usize,
}

impl SubnetRecord {
    pub fn from_result(result: &(Ipv4Network, SubnetInfo, usize)) -> Self {
        let (subnet, info, count) = result;
        Self {
            subnet: subnet.to_string(),
            source: info.source.clone(),
            country: info.country.clone(),
            city: info.city.clone(),
            asn: info.asn,
            as_name: info.as_name.clone(),
            active_hosts: *count,
        }
    }
}

pub fn save_results_to_file(
    results: &[(Ipv4Network, SubnetInfo, usize)],
    filename: &str,
) -> anyhow::Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = Path::new(filename).parent() {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(filename)?;
    let mut writer = BufWriter::new(file);

    writeln!(
        writer,
        "subnet;source;country;city;asn;as_name;active_hosts"
    )?;

    // Записываем данные
    for (subnet, info, count) in results {
        writeln!(
            writer,
            "{};{};{};{};{};{};{}",
            subnet,
            info.source,
            info.country,
            info.city,
            info.asn,
            info.as_name,
            count
        )?;
    }

    writer.flush()?;
    println!("CSV saved: {}", filename);

    Ok(())
}

pub fn save_results_to_json(
    results: &[(Ipv4Network, SubnetInfo, usize)],
    filename: &str,
) -> anyhow::Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = Path::new(filename).parent() {
        fs::create_dir_all(parent)?;
    }

    let records: Vec<SubnetRecord> = results
        .iter()
        .map(|(subnet, info, count)| SubnetRecord {
            subnet: subnet.to_string(),
            source: info.source.clone(),
            country: info.country.clone(),
            city: info.city.clone(),
            asn: info.asn,
            as_name: info.as_name.clone(),
            active_hosts: *count,
        })
        .collect();

    let json = serde_json::to_string_pretty(&records)?;
    fs::write(filename, json)?;
    println!("JSON saved: {}", filename);

    Ok(())
}

pub fn append_result_to_csv(
    result: &(Ipv4Network, SubnetInfo, usize),
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

    if should_write_header {
        writeln!(writer, "subnet;source;country;city;asn;as_name;active_hosts")?;
    }

    let record = SubnetRecord::from_result(result);
    writeln!(
        writer,
        "{};{};{};{};{};{};{}",
        record.subnet,
        record.source,
        record.country,
        record.city,
        record.asn,
        record.as_name,
        record.active_hosts
    )?;
    writer.flush()?;

    Ok(())
}

pub fn append_result_to_jsonl(
    result: &(Ipv4Network, SubnetInfo, usize),
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