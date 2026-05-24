use std::{
    net::{SocketAddr, TcpStream, ToSocketAddrs, IpAddr},
    time::{Duration, Instant},
};
use std::net::Ipv4Addr;
use rayon::prelude::*;
use reqwest::blocking::Client;


fn clamp_to_timeout_ms(elapsed_ms: f64, timeout: Duration) -> f64 {
    let max_ms = timeout.as_secs_f64() * 1_000.0;
    if elapsed_ms > max_ms {
        max_ms
    } else {
        elapsed_ms
    }
}

fn probe_once(addr: SocketAddr, to: Duration) -> (bool, f64) {
    let start = Instant::now();
    let ok = TcpStream::connect_timeout(&addr, to).is_ok();
    let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
    let rtt = clamp_to_timeout_ms(elapsed_ms, to);
    (ok, rtt)
}

fn normalize_sni_host(host: &str) -> String {
    host.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(host)
        .split(':')
        .next()
        .unwrap_or(host)
        .to_string()
}

pub fn probe_tcp_with_sni(ip: IpAddr, port: u16, sni_host: &str, to: Duration) -> anyhow::Result<bool> {
    let host = normalize_sni_host(sni_host);
    let addr = SocketAddr::new(ip, port);
    let url = if port == 443 {
        format!("https://{host}/")
    } else {
        format!("https://{host}:{port}/")
    };

    let client = Client::builder()
        .timeout(to)
        .danger_accept_invalid_certs(true)
        .resolve(&host, addr)
        .build()?;

    Ok(client
        .get(url)
        .header("User-Agent", "curl/7.88.1")
        .send()
        .is_ok())
}

pub fn probe_tcp_with_optional_sni(
    ip: IpAddr,
    port: u16,
    sni_host: Option<&str>,
    to: Duration,
) -> (bool, f64) {
    if let Some(sni_host) = sni_host {
        let start = Instant::now();
        let ok = probe_tcp_with_sni(ip, port, sni_host, to).unwrap_or(false);
        let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
        return (ok, clamp_to_timeout_ms(elapsed_ms, to));
    }

    let addr = SocketAddr::new(ip, port);
    probe_once(addr, to)
}

fn string_to_ip(address: &String) -> anyhow::Result<IpAddr> {
    let ip: IpAddr = if address.parse::<Ipv4Addr>().is_err() {
        let endpoint_host: String = if !address.contains(":") {
            format!("{}:{}", address, 80)
        } else {
            address.clone()
        };
        let addrs: Vec<_> = match endpoint_host.to_socket_addrs() {
            Ok(addrs) => addrs.collect(),
            Err(_) => vec![],
        };
        if addrs.is_empty() {
            anyhow::bail!("Failed to resolve address");
        } else {
            addrs[0].ip()
        }
    } else {
        address.parse()?
    };
    Ok(ip)
}

pub async fn test_tcp_ping(
    address: &String,
    ports: &Vec<u16>,
    sni_host: Option<&str>,
) -> anyhow::Result<Vec<(u16, bool, f64)>> {
    let ip = string_to_ip(address)?;

    let results: Vec<(u16, bool, f64)> = ports.par_iter().map(|port| {
        let (ok, elapsed_ms) =
            probe_tcp_with_optional_sni(ip, *port, sni_host, Duration::from_secs(2));
        println!("{}:{} {} {:.4}", address, port, ok, elapsed_ms);
        (*port, ok, elapsed_ms)
    }).collect();

    Ok(results)
}