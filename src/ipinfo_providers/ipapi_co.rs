use std::error::Error;
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
struct IpApiCoResponse {
    ip: Option<String>,
    network: Option<String>,
    _version: Option<String>,
    city: Option<String>,
    _region: Option<String>,
    _region_code: Option<String>,
    _country: Option<String>,
    _country_name: Option<String>,
    country_code: Option<String>,
    _country_code_iso3: Option<String>,
    _country_capital: Option<String>,
    _country_tld: Option<String>,
    _continent_code: Option<String>,
    _in_eu: Option<bool>,
    _postal: Option<String>,
    _latitude: Option<f32>,
    _longitude: Option<f32>,
    _timezone: Option<String>,
    _utc_offset: Option<String>,
    _country_calling_code: Option<String>,
    _currency: Option<String>,
    _currency_name: Option<String>,
    _languages: Option<String>,
    _country_area: Option<f64>,
    _country_population: Option<u32>,
    asn: Option<String>,
    org: Option<String>,

}

impl IpApiCoResponse {
    fn to_ip_information(&self) -> Result<IpApiCo> {

        Ok(IpApiCo {
            _ip: self.ip.clone().unwrap_or("0.0.0.0".to_string()).parse()?,
            network: self.network.clone(),
            city: self.city.clone(),
            country_code: self.country_code.clone(),
            asn: self.asn.clone(),
            org: self.org.clone(),
        })
    }
}

#[derive(Debug)]
pub struct IpApiCo {
    pub _ip: IpAddr,
    pub network: Option<String>,
    pub city: Option<String>,
    pub country_code: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
}

impl Default for IpApiCo {
    fn default() -> Self {
        IpApiCo {
            _ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            network: None,
            city: None,
            country_code: None,
            asn: None,
            org: None,
        }
    }
}

pub struct IpApiCoProvider {
    client: Client,
    base_url: String,
}

impl IpApiCoProvider {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "https://ipapi.co".to_string(),
        }
    }

    pub async fn get_info(&self, ip: &str) -> Result<IpApiCo> {

        let url = format!("{}/{}/json/", self.base_url, ip);

        let response = self.client
            .get(&url)
            .header("User-Agent", "curl/1.0)")
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .context("Error request ipapi.co")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "HTTP error ipapi.co: {}",
                response.status()
            ));
        }

        // let api_response: IpApiCoResponse = response
        //     .json()
        //     .await
        //     .context("Parsing JSON ipapi.co error")?;

        let api_response: IpApiCoResponse = match response.json().await {
            Ok(api_response) => api_response,
            Err(e) => {
                return Err(anyhow::anyhow!("Parsing JSON ipwho.is error. {}", e.source().unwrap()));
            },
        };

        api_response.to_ip_information()
    }
}