use serde::{Deserialize};
use std::net::IpAddr;
use anyhow::{Result, Context};
use reqwest::Client;
use std::time::Duration;
// use serde_with::{serde_as, DisplayFromStr};

#[derive(Debug, Deserialize, Default)]
struct IpInfoResponse {
    ip: String,
    hostname: Option<String>,
    city: Option<String>,
    country: Option<String>,
    org: Option<String>,
    #[serde(default)]
    _loc: Option<String>, // coords "lat,lng"
    #[serde(default)]
    _region: Option<String>,
    #[serde(default)]
    _timezone: Option<String>,
}

impl IpInfoResponse {
    fn to_ip_information(&self) -> Result<IpInfo> {

        Ok(IpInfo {
            _ip: self.ip.parse()?,
            hostname: self.hostname.clone(),
            city: self.city.clone(),
            country: self.country.clone(),
            org: self.org.clone(),
        })
    }
}

#[derive(Debug)]
pub struct IpInfo {
    pub _ip: IpAddr,
    pub hostname: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub org: Option<String>,
}

impl Default for IpInfo {
    fn default() -> Self {
        IpInfo {
            _ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            hostname: None,
            city: None,
            country: None,
            org: None,
        }
    }
}

pub struct IpInfoProvider {
    client: Client,
    base_url: String,
}

impl IpInfoProvider {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "https://ipinfo.io".to_string(),
        }
    }

    pub async fn get_info(&self, ip: &str) -> Result<IpInfo> {
        let url = format!("{}/{}/json", self.base_url, ip);

        let request = self.client
            .get(&url)
            // .header("User-Agent", "Mozilla/5.0 (compatible; RustIPChecker/1.0)")
            .timeout(Duration::from_secs(5));

        let response = request
            .send()
            .await
            .context("Error request ipinfo.io")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "HTTP error ipinfo.io: {}",
                response.status()
            ));
        }

        let api_response: IpInfoResponse = response
            .json()
            .await
            .context("Parsing JSON ipinfo.io error")?;

        api_response.to_ip_information()
    }
}