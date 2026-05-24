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
struct IpWhoIsResponse {
    ip: Option<String>,
    success: Option<bool>,
    #[serde(rename = "type")]
    _ip_type: Option<String>,
    _continent: Option<String>,
    #[serde(rename = "continent_code")]
    _continent_code: Option<String>,
    _country: Option<String>,
    #[serde(rename = "country_code")]
    country_code: Option<String>,
    _region: Option<String>,
    #[serde(rename = "region_code")]
    _region_code: Option<String>,
    city: Option<String>,
    _latitude: Option<f32>,
    _longitude: Option<f32>,
    #[serde(rename = "is_eu")]
    _is_eu: Option<bool>,
    _postal: Option<String>,
    #[serde(rename = "calling_code")]
    _calling_code: Option<String>,
    _capital: Option<String>,
    _borders: Option<String>,
    _flag: Option<IpWhoIsFlagResponse>,
    connection: Option<IpWhoIsConnectionResponse>,
    _timezone: Option<IpWhoIsTimezoneResponse>,
}

#[derive(Debug, Deserialize)]
struct IpWhoIsFlagResponse {
    _img: Option<String>,
    _emoji: Option<String>,
    #[serde(rename = "emoji_unicode")]
    _emoji_unicode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpWhoIsConnectionResponse {
    asn: Option<u32>,
    org: Option<String>,
    isp: Option<String>,
    domain: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpWhoIsTimezoneResponse {
    _id: Option<String>,
    _abbr: Option<String>,
    #[serde(rename = "is_dst")]
    _is_dst: Option<bool>,
    _offset: Option<u32>,
    _utc: Option<String>,
    #[serde(rename = "current_time")]
    _current_time: Option<String>,
}

impl IpWhoIsResponse {
    fn to_ip_information(&self) -> Result<IpWhoIs> {
        if self.success.unwrap_or(false) != true {
            return Err(anyhow::anyhow!("API return status: {}", self.success.unwrap_or(false)));
        }

        let (asn, org, isp, domain) = if self.connection.is_some() {
            let connection = self.connection.as_ref().unwrap();
            (
                connection.asn,
                connection.org.clone(),
                connection.isp.clone(),
                connection.domain.clone()
            )
        } else {
            (Some(0), None, None, None)
        };

        Ok(IpWhoIs {
            _ip: self.ip.clone().unwrap_or("0.0.0.0".to_string()).parse()?,
            country_code: self.country_code.clone(),
            city: self.city.clone(),
            asn,
            _org: org,
            isp,
            domain,
        })
    }
}

#[derive(Debug)]
pub struct IpWhoIs {
    pub _ip: IpAddr,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub _org: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
}

impl Default for IpWhoIs {
    fn default() -> Self {
        IpWhoIs {
            _ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            country_code: None,
            city: None,
            asn: Some(0),
            _org: None,
            isp: None,
            domain: None,
        }
    }
}

pub struct IpWhoIsProvider {
    client: Client,
    base_url: String,
}

impl IpWhoIsProvider {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "http://ipwho.is".to_string(),
        }
    }

    pub async fn get_info(&self, ip: &str) -> Result<IpWhoIs> {

        let url = format!("{}/{}", self.base_url, ip);

        let response = self.client
            .get(&url)
            .header("User-Agent", "Mozilla/5.0 (compatible; RustIPChecker/1.0)")
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .context("Error request ipwho.is")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "HTTP error ipwho.is: {}",
                response.status()
            ));
        }

        // let api_response: IpWhoIsResponse = response
        //     .json()
        //     .await
        //     .context("Parsing JSON ipwho.is error")?;

        let api_response: IpWhoIsResponse = match response.json().await {
            Ok(api_response) => api_response,
            Err(e) => {
                return Err(anyhow::anyhow!("Parsing JSON ipwho.is error. {}", e.source().unwrap()));
            },
        };

        api_response.to_ip_information()
    }
}