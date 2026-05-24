use std::{
    net::{SocketAddr, TcpStream, ToSocketAddrs, IpAddr},
    time::{Duration, Instant},
};
use std::net::Ipv4Addr;
use rayon::prelude::*;
use reqwest::blocking::Client;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};


fn clamp_to_timeout_ms(elapsed_ms: f64, timeout: Duration) -> f64 {
    let max_ms = timeout.as_secs_f64() * 1_000.0;
    if elapsed_ms > max_ms {
        max_ms
    } else {
        elapsed_ms
    }
}

fn probe_once(addr: SocketAddr, to: Duration, network_interface: Option<&str>) -> (bool, f64) {
    let start = Instant::now();
    let ok = connect_timeout(addr, to, network_interface).is_ok();
    let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
    let rtt = clamp_to_timeout_ms(elapsed_ms, to);
    (ok, rtt)
}

fn connect_timeout(
    addr: SocketAddr,
    to: Duration,
    network_interface: Option<&str>,
) -> std::io::Result<()> {
    let Some(network_interface) = network_interface else {
        return TcpStream::connect_timeout(&addr, to).map(|_| ());
    };

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.bind_device(Some(network_interface.as_bytes()))?;
        socket.connect_timeout(&SockAddr::from(addr), to)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = network_interface;
        TcpStream::connect_timeout(&addr, to).map(|_| ())
    }
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

pub fn probe_tcp_with_sni(
    ip: IpAddr,
    port: u16,
    sni_host: &str,
    to: Duration,
    network_interface: Option<&str>,
) -> anyhow::Result<bool> {
    let host = normalize_sni_host(sni_host);
    let addr = SocketAddr::new(ip, port);
    let url = if port == 443 {
        format!("https://{host}/")
    } else {
        format!("https://{host}:{port}/")
    };

    let mut builder = Client::builder()
        .timeout(to)
        .danger_accept_invalid_certs(true)
        .resolve(&host, addr);

    if let Some(network_interface) = network_interface {
        builder = builder.interface(network_interface);
    }

    let client = builder.build()?;

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
    network_interface: Option<&str>,
    to: Duration,
) -> (bool, f64) {
    if let Some(sni_host) = sni_host {
        let start = Instant::now();
        let ok = probe_tcp_with_sni(ip, port, sni_host, to, network_interface).unwrap_or(false);
        let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
        return (ok, clamp_to_timeout_ms(elapsed_ms, to));
    }

    let addr = SocketAddr::new(ip, port);
    probe_once(addr, to, network_interface)
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
    network_interface: Option<&str>,
) -> anyhow::Result<Vec<(u16, bool, f64)>> {
    let ip = string_to_ip(address)?;

    let results: Vec<(u16, bool, f64)> = ports.par_iter().map(|port| {
        let (ok, elapsed_ms) =
            probe_tcp_with_optional_sni(ip, *port, sni_host, network_interface, Duration::from_secs(2));
        println!("{}:{} {} {:.4}", address, port, ok, elapsed_ms);
        (*port, ok, elapsed_ms)
    }).collect();

    Ok(results)
}