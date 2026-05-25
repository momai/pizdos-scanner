use std::time::Duration;

use anyhow::Result;
use tokio::time::sleep;

use crate::{
    init::{Config, ConfigSocketType},
    ipinfo::get_providers_info,
    tcp_ping, utils::get_current_ip,
};

pub async fn run_myip() -> Result<()> {
    let ip = get_current_ip().await;
    match ip {
        Ok(ip) => println!("current ip: {}", ip),
        Err(e) => println!("ERR {}", e),
    }
    Ok(())
}

pub async fn run_info(config: &Config, ip: String) -> Result<()> {
    get_providers_info(config, &ip).await?;

    let ip_parsed: std::net::IpAddr = ip.parse()?;
    let hostname = dns_lookup::lookup_addr(&ip_parsed.clone()).unwrap_or_else(|_| "None".to_string());
    println!("PTR for {} - {}", ip, hostname);

    let socket = match &config.socket_type {
        Some(ConfigSocketType::DGRAM) => ping::DGRAM,
        Some(ConfigSocketType::RAW) => ping::RAW,
        None => ping::DGRAM,
    };

    let mut pings: Vec<Duration> = vec![];
    for _ in 0..3 {
        let mut ping = ping::new(ip_parsed);
        ping.socket_type(socket).timeout(Duration::from_secs(1));
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(network_interface) = config.network_interface() {
            ping.bind_device(network_interface);
        }

        match ping.send() {
            Ok(r) => pings.push(r.rtt),
            Err(_e) => {}
        }
        sleep(Duration::from_millis(300)).await
    }

    println!("PING for {} - {:?}", ip_parsed, pings);
    Ok(())
}

pub async fn run_test(
    config: &Config,
    ip: Option<String>,
    ports: Option<Vec<u16>>,
    sni: Option<String>,
) -> Result<()> {
    if ip.is_some() && ports.is_some() {
        tcp_ping::test_tcp_ping(
            &String::from(ip.unwrap()),
            &ports.unwrap(),
            sni.as_deref(),
            config.network_interface(),
        )
        .await?;
    } else {
        println!("Please specify ip and ports");
    }
    Ok(())
}
