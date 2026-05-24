use std::{
    net::IpAddr,
    path::Path,
    sync::Arc,
};
use anyhow::{Context, Result};
use reqwest::Client;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::fs as tokio_fs;
use tokio::io::AsyncWriteExt;
use futures_util::StreamExt;
use maxminddb::{geoip2, Reader};
use crate::init;
use crate::init::Config;

async fn download_from_url(
    client: &Client,
    url: &String,
    file_path: &Path,
    description: &str,
) -> Result<()> {
    println!("Download {} from {} ...", description, url);

    let response = client
        .get(url)
        .send()
        .await
        .context(format!("Can't connect to {}", url))?;

    // Проверяем статус ответа
    if !response.status().is_success() {
        anyhow::bail!("HTTP error {} for download {}", response.status(), url);
    }

    // Получаем размер файла для прогресс-бара
    let total_size = response
        .content_length()
        .unwrap_or(0);

    // Создаем временный файл
    let temp_path = file_path.with_extension("tmp");

    // Создаем прогресс-бар
    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
            .progress_chars("#>-")
    );
    pb.set_message(format!("Downloading {}", description));

    // Читаем данные по частям и пишем в файл
    let mut file = tokio_fs::File::create(&temp_path).await?;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        pb.inc(chunk.len() as u64);
    }

    pb.finish_with_message("Download complete");

    // Перемещаем временный файл в целевой
    tokio_fs::rename(&temp_path, file_path).await?;

    // Проверяем размер скачанного файла
    let metadata = tokio_fs::metadata(file_path).await?;
    if metadata.len() == 0 {
        anyhow::bail!("Downloaded file is empty");
    }

    println!("{} saved ({} Mb) to {:?}",
             description, metadata.len() / (1024 * 1024), file_path);

    Ok(())
}

pub async fn download_db(
    urls: &Vec<String>,
    file_path: &Path,
    description: &str,
) -> Result<()> {

    let client = Client::new();
    for url in urls {
        match download_from_url(&client, &url, file_path, description).await {
            Ok(_) => return Ok(()),
            Err(_) => continue
        }
    }

    anyhow::bail!("Download {} failed", description);
}

pub async fn download_dbs(config: &Config) -> Result<()> {
    let city_path = Path::new(config.geoip_city_db.as_ref().unwrap());
    let asn_path = Path::new(config.geoip_asn_db.as_ref().unwrap());

    for db_update in config.db_update.as_ref().unwrap() {
        match db_update.db_type {
            init::ConfigDBType::GeoLite2City => download_db(&db_update.update_urls, city_path, "GeoLite2City").await?,
            init::ConfigDBType::GeoLite2ASN => download_db(&db_update.update_urls, asn_path, "GeoLite2ASN").await?,
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct SubnetInfo {
    pub source: String,
    pub country: String,
    pub city: String,
    pub asn: u32,
    pub as_name: String,
}

impl SubnetInfo {
    pub fn new() -> Self {
        Self {
            source: "N/A".to_string(),
            country: "N/A".to_string(),
            city: "N/A".to_string(),
            asn: 0,
            as_name: "N/A".to_string(),
        }
    }

    pub fn with_source(source: &str) -> Self {
        let mut info = Self::new();
        info.source = source.to_string();
        info
    }
}

#[derive(Clone)]
pub struct GeoIpService {
    pub reader_city: Arc<Reader<Vec<u8>>>,
    pub reader_asn: Arc<Reader<Vec<u8>>>,
}

impl GeoIpService {
    pub fn new(city_db_path: &str, asn_db_path: &str) -> anyhow::Result<Self> {
        let reader_city = Reader::open_readfile(city_db_path)
            .context("Failed to open GeoLite2-City database")?;
        let reader_asn = Reader::open_readfile(asn_db_path)
            .context("Failed to open GeoLite2-ASN database")?;

        Ok(Self {
            reader_city: Arc::new(reader_city),
            reader_asn: Arc::new(reader_asn),
        })
    }

    pub fn get_ip_info(&self, ip: IpAddr) -> anyhow::Result<SubnetInfo> {
        let mut info = SubnetInfo::new();

        let result_city = self.reader_city.lookup(ip)?;
        let result_asn = self.reader_asn.lookup(ip)?;

        match result_city.decode::<geoip2::City>() {
            Ok(city) => {
                match city {
                    Some(city) => {
                        info.city = city.city.names.english.unwrap_or("N/A").to_string();
                        info.country = city.country.iso_code.unwrap_or("N/A").to_string();
                    },
                    None => {},
                }
            },
            Err(e) => return Err(e.into()),
        };

        match result_asn.decode::<geoip2::Asn>() {
            Ok(asn) => {
                match asn {
                    Some(asn) => {
                        info.asn = asn.autonomous_system_number.unwrap_or(0);
                        info.as_name = asn.autonomous_system_organization.unwrap_or("N/A").to_string();
                    },
                    None => {},
                }
            },
            Err(e) => return Err(e.into()),
        };

        Ok(info)
    }
}