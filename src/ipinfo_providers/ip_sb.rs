use serde::{Deserialize};
use std::net::IpAddr;
use anyhow::{Result, Context};
use reqwest::Client;
use std::time::Duration;
use serde_with::{
    serde_as,
    // DisplayFromStr
};

#[serde_as]
#[derive(Debug, Deserialize)]
struct IpSbResponse {
    organization: Option<String>,
    _region: Option<String>,
    isp: Option<String>,
    _region_code: Option<String>,
    asn_organization: Option<String>,
    city: Option<String>,
    asn: Option<u32>,
    _postal_code: Option<String>,
    _offset: Option<u32>,
    _latitude: Option<f32>,
    ip: Option<String>,
    _continent_code: Option<String>,
    _timezone: Option<String>,
    _country: Option<String>,
    _longitude: Option<f32>,
    country_code: Option<String>,
}

impl IpSbResponse {
    fn to_ip_information(&self) -> Result<IpSb> {

        Ok(IpSb {
            _ip: self.ip.clone().unwrap_or("0.0.0.0".to_string()).parse()?,
            _organization: self.organization.clone(),
            _isp: self.isp.clone(),
            asn_organization: self.asn_organization.clone(),
            city: self.city.clone(),
            asn: self.asn.clone(),
            country_code: self.country_code.clone(),
        })
    }
}

#[derive(Debug)]
pub struct IpSb {
    pub _ip: IpAddr,
    pub _organization: Option<String>,
    pub _isp: Option<String>,
    pub asn_organization: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub country_code: Option<String>,
}

impl Default for IpSb {
    fn default() -> Self {
        IpSb {
            _ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            _organization: None,
            _isp: None,
            asn_organization: None,
            city: None,
            asn: Some(0),
            country_code: None,
        }
    }
}

pub struct IpSbProvider {
    client: Client,
    base_url: String,
}

impl IpSbProvider {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "https://api.ip.sb/geoip".to_string(),
        }
    }

    pub async fn get_info(&self, ip: &str) -> Result<IpSb> {

        let url = format!("{}/{}", self.base_url, ip);

        let response = self.client
            .get(&url)
            // .header("User-Agent", "Mozilla/5.0 (compatible; RustIPChecker/1.0)")
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .context("Error request api.ip.sb")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "HTTP error api.ip.sb: {}",
                response.status()
            ));
        }

        let api_response: IpSbResponse = response
            .json()
            .await
            .context("Parsing JSON api.ip.sb error")?;

        api_response.to_ip_information()
    }
}