use serde::Deserialize;
use std::{
    fs::{self, File},
    io::Read
};
use std::path::Path;

const CITY_PRIMARY_URL: &str = "https://git.io/GeoLite2-City.mmdb";
const CITY_MIRROR_URL: &str = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb";
const ASN_PRIMARY_URL: &str = "https://git.io/GeoLite2-ASN.mmdb";
const ASN_MIRROR_URL: &str = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb";

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub geoip_city_db: Option<String>,
    pub geoip_asn_db: Option<String>,
    pub geoip_dat_path: Option<String>,
    pub geoip_codes: Option<Vec<String>>,
    pub subnets: Vec<String>,
    pub operator: Option<String>,
    pub endpoint: String,
    pub results_dir: Option<String>,
    pub resume_state_dir: Option<String>,
    pub resume: Option<bool>,
    pub tcp_ports: Option<Vec<u16>>,
    pub tcp_sni_host: Option<String>,
    pub socket_type: Option<ConfigSocketType>,
    pub ping_type: Vec<ConfigPingType>,
    pub logger_filetype: Vec<ConfigSaveResultFileType>,
    pub ipinfo_providers: Vec<String>,
    pub task: Option<SubnetsScan>,
    pub db_update: Option<Vec<ConfigDBUpdate>>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub enum ConfigPingType {
    TCP,
    ICMP
}
#[derive(Debug, Deserialize, Clone)]
pub enum ConfigSocketType {
    DGRAM,
    RAW
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub enum ConfigDBType {
    GeoLite2City,
    GeoLite2ASN
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConfigDBUpdate {
    pub db_type: ConfigDBType,
    pub update_urls: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub enum ConfigSaveResultFileType {
    Csv,
    Json
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubnetsScan {
    pub stop_every_times: u32,
    pub stop_action: ConfigStopAction,
    pub change_ip_url: Option<String>,
    pub delay_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub enum ConfigStopAction {
    Prompt,
    ChangeIp,
    Delay
}

impl Config {
    pub fn results_dir(&self) -> &str {
        self.results_dir.as_deref().unwrap_or("results")
    }

    pub fn tcp_ports(&self) -> Vec<u16> {
        self.tcp_ports.clone().unwrap_or_else(|| vec![443])
    }

    pub fn geoip_dat_path(&self) -> &str {
        self.geoip_dat_path.as_deref().unwrap_or("geoip.dat")
    }

    pub fn geoip_codes(&self) -> Vec<String> {
        self.geoip_codes.clone().unwrap_or_default()
    }

    pub fn resume_state_dir(&self) -> &str {
        self.resume_state_dir.as_deref().unwrap_or("results/state")
    }

    pub fn resume_enabled(&self) -> bool {
        self.resume.unwrap_or(true)
    }

    pub fn load(path: &str) -> anyhow::Result<Self> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(e) => anyhow::bail!("Can't open config file {}: {}", path, e),
        };

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let mut config: Config = match toml::from_str(&contents) {
            Ok(config) => config,
            Err(e) => anyhow::bail!("Can't parse config file {}: {}", path, e),
        };

        if !config.geoip_city_db.is_some() {
            config.geoip_city_db = Some("db/GeoLite2-City.mmdb".to_string());
        }

        if !config.geoip_asn_db.is_some() {
            config.geoip_asn_db = Some("db/GeoLite2-ASN.mmdb".to_string());
        }

        if config.socket_type.is_none() {
            match std::env::consts::OS {
                // "windows" => {
                //     config.socket_type = Some(ConfigSocketType::RAW);
                // },
                "linux" => {
                    config.socket_type = Some(ConfigSocketType::DGRAM);
                },
                _ => {
                    config.socket_type = Some(ConfigSocketType::RAW);
                }
            }
        }

        if config.db_update.is_none() {
            let db_city = ConfigDBUpdate {
                db_type: ConfigDBType::GeoLite2City,
                update_urls: vec![CITY_PRIMARY_URL.to_string(), CITY_MIRROR_URL.to_string()],
            };

            let db_asn = ConfigDBUpdate {
                db_type: ConfigDBType::GeoLite2ASN,
                update_urls: vec![ASN_PRIMARY_URL.to_string(), ASN_MIRROR_URL.to_string()],
            };

            config.db_update = Some(vec![db_city, db_asn]);
        }

        if config.task.is_some() {
            match config.task.as_ref().unwrap().stop_action {
                ConfigStopAction::ChangeIp => {
                    if config.task.as_ref().unwrap().change_ip_url.is_none() {
                        anyhow::bail!("change_ip_url is required for stop_action = ChangeIp");
                    }
                },
                ConfigStopAction::Delay => {
                    if config.task.as_ref().unwrap().delay_seconds.is_none() {
                        anyhow::bail!("delay_seconds is required for stop_action = Delay");
                    }
                },
                _ => {},
            }
        }

        // println!("{:#?}", config);

        Ok(config)
    }
}

fn check_dir(path: &Path) -> anyhow::Result<()> {
    let is_exist = fs::exists(path)?;
    if !is_exist {
        fs::create_dir(path)?;
    } else {
        if !fs::metadata(path)?.is_dir() {
            anyhow::bail!("{} is not a directory", path.display());
        }
    }
    Ok(())
}

pub fn init_env() -> anyhow::Result<()> {
    check_dir(&Path::new("db"))?;
    check_dir(&Path::new("results"))?;
    check_dir(&Path::new("results/state"))?;
    Ok(())
}