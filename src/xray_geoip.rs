use anyhow::Context;
use ipnetwork::Ipv4Network;
use prost::Message;
use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;

#[derive(Clone, PartialEq, Message)]
struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIp {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    inverse_match: bool,
    #[prost(bytes = "vec", tag = "4")]
    resource_hash: Vec<u8>,
    #[prost(string, tag = "5")]
    code: String,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoIp>,
}

#[derive(Debug, Clone)]
pub struct GeoIpCodeInfo {
    pub code: String,
    pub cidr_count: usize,
    pub ipv4_count: usize,
    pub ipv6_count: usize,
}

#[derive(Debug, Clone)]
pub struct GeoIpLoadResult {
    pub networks: Vec<Ipv4Network>,
    pub matched_codes: Vec<String>,
    pub skipped_ipv6: usize,
}

fn load_list(path: &str) -> anyhow::Result<GeoIpList> {
    let bytes = fs::read(path).with_context(|| format!("Can't read geoip dat file {}", path))?;
    GeoIpList::decode(bytes.as_slice()).with_context(|| format!("Can't decode geoip dat file {}", path))
}

fn entry_code(entry: &GeoIp) -> String {
    if !entry.code.is_empty() {
        entry.code.clone()
    } else {
        entry.country_code.clone()
    }
}

fn cidr_to_ipv4(cidr: &Cidr) -> anyhow::Result<Option<Ipv4Network>> {
    if cidr.ip.len() != 4 {
        return Ok(None);
    }
    if cidr.prefix > 32 {
        anyhow::bail!("Invalid IPv4 prefix {}", cidr.prefix);
    }

    let ip = Ipv4Addr::new(cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3]);
    let network = Ipv4Network::new(ip, cidr.prefix as u8)?;
    Ipv4Network::new(network.network(), network.prefix()).map(Some).map_err(Into::into)
}

pub fn list_codes(path: &str) -> anyhow::Result<Vec<GeoIpCodeInfo>> {
    let list = load_list(path)?;
    let mut codes: Vec<GeoIpCodeInfo> = list
        .entry
        .iter()
        .map(|entry| {
            let ipv4_count = entry.cidr.iter().filter(|cidr| cidr.ip.len() == 4).count();
            let ipv6_count = entry.cidr.iter().filter(|cidr| cidr.ip.len() == 16).count();
            GeoIpCodeInfo {
                code: entry_code(entry),
                cidr_count: entry.cidr.len(),
                ipv4_count,
                ipv6_count,
            }
        })
        .collect();

    codes.sort_by(|a, b| a.code.to_lowercase().cmp(&b.code.to_lowercase()));
    Ok(codes)
}

pub fn load_ipv4_cidrs(path: &str, wanted_codes: &[String]) -> anyhow::Result<GeoIpLoadResult> {
    let list = load_list(path)?;
    let wanted: HashSet<String> = wanted_codes.iter().map(|code| code.to_lowercase()).collect();
    let mut matched_codes = Vec::new();
    let mut skipped_ipv6 = 0usize;
    let mut seen = HashSet::new();
    let mut networks = Vec::new();

    for entry in list.entry {
        let code = entry_code(&entry);
        if !wanted.contains(&code.to_lowercase()) {
            continue;
        }

        matched_codes.push(code);
        for cidr in &entry.cidr {
            match cidr_to_ipv4(cidr)? {
                Some(network) => {
                    let key = (u32::from(network.network()), network.prefix());
                    if seen.insert(key) {
                        networks.push(network);
                    }
                }
                None => skipped_ipv6 += 1,
            }
        }
    }

    networks.sort_by_key(|network| (u32::from(network.network()), network.prefix()));
    matched_codes.sort_by_key(|code| code.to_lowercase());

    Ok(GeoIpLoadResult {
        networks,
        matched_codes,
        skipped_ipv6,
    })
}
