use serde::{Deserialize};
use std::net::IpAddr;
use anyhow::{Result, Context};
use reqwest::Client;
use std::time::Duration;
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Debug, Deserialize)]
struct IpApiResponse {
    #[serde(rename = "query")]
    ip: String,
    status: String,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    #[serde_as(as = "Option<DisplayFromStr>")]
    as_number: Option<String>,
    asname: Option<String>,
    reverse: Option<String>,
}

impl IpApiResponse {
    fn to_ip_information(&self) -> Result<IpApi> {
        if self.status != "success" {
            return Err(anyhow::anyhow!("API return status: {}", self.status));
        }

        Ok(IpApi {
            _ip: self.ip.parse()?,
            country_code: self.country_code.clone(),
            city: self.city.clone(),
            _isp: self.isp.clone(),
            _org: self.org.clone(),
            as_number: self.as_number.clone(),
            as_name: self.asname.clone(),
            reverse: self.reverse.clone(),
        })
    }
}

#[derive(Debug)]
pub struct IpApi {
    pub _ip: IpAddr,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub _isp: Option<String>,
    pub _org: Option<String>,
    pub as_number: Option<String>,
    pub as_name: Option<String>,
    pub reverse: Option<String>,
}

impl Default for IpApi {
    fn default() -> Self {
        IpApi {
            _ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            country_code: None,
            city: None,
            _isp: None,
            _org: None,
            as_number: None,
            as_name: None,
            reverse: None,
        }
    }
}

pub struct IpApiProvider {
    client: Client,
    base_url: String,
}

impl IpApiProvider {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "http://ip-api.com/json".to_string(),
        }
    }

    pub async fn get_info(&self, ip: &str) -> Result<IpApi> {

        let url = format!("{}/{}?fields=status,message,countryCode,city,isp,org,as,asname,reverse,query", self.base_url, ip);

        let response = self.client
            .get(&url)
            // .header("User-Agent", "Mozilla/5.0 (compatible; RustIPChecker/1.0)")
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .context("Error request ip-api.com")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "HTTP error ip-api.com: {}",
                response.status()
            ));
        }

        let api_response: IpApiResponse = response
            .json()
            .await
            .context("Parsing JSON ip-api.com error")?;

        api_response.to_ip_information()
    }
}