use std::net::IpAddr;
use std::net::ToSocketAddrs;
use crate::init::Config;
use crate::ipinfo_providers;
use crate::geoip::GeoIpService;

struct GeoInfo {
    provider: String,
    country_code: String,
    city: String,
    as_number: String,
    as_name: String,
    reverse: String,
}

pub async fn get_providers_info(config: &Config, ip: &str) -> anyhow::Result<()> {

    if !config.ipinfo_providers.is_empty() {

        let target_ip = if ip.parse::<IpAddr>().is_err() {
            let addrs: Vec<_> = match format!("{}:80", ip).to_socket_addrs() {
                Ok(addrs) => addrs.collect(),
                Err(e) => return Err(e.into()),
            };
            let checking_ip = addrs.first().unwrap().ip().to_string();
            println!(
                "{} => {:?}\nChecking IP: {}",
                ip, addrs.iter().map(|addr| addr.ip()).collect::<Vec<_>>(), checking_ip
            );
            checking_ip
        } else {
            println!("Checking IP: {}", ip);
            ip.to_string()
        };

        let mut geo_info = Vec::new();

        geo_info.push(GeoInfo {
            provider: String::from("PROVIDER"),
            country_code: String::from("CC"),
            city: String::from("CITY"),
            as_number: String::from("ASN"),
            as_name: String::from("AS NAME"),
            reverse: String::from("PTR, DOMAIN, SUBNET"),
        });

        if config.ipinfo_providers.contains(&String::from("ip-api.com")) {
            let ip_api_result = ipinfo_providers::ip_api::IpApiProvider::new();
            let resp = ip_api_result.get_info(&target_ip).await;
            match resp {
                Ok(info) => {
                    let provider = String::from("ip-api.com");
                    let country_code = info.country_code.unwrap_or_default();
                    let city = info.city.unwrap_or_default();
                    let as_number = info.as_number.unwrap_or_default();
                    let as_name = info.as_name.unwrap_or_default();
                    let reverse = info.reverse.unwrap_or_default();

                    geo_info.push(GeoInfo {
                        provider,
                        country_code,
                        city,
                        as_number,
                        as_name,
                        reverse,
                    })
                },
                Err(_) => {}
            }
        }

        if config.ipinfo_providers.contains(&String::from("ipinfo.com")) {
            let ipinfo_result = ipinfo_providers::ipinfo::IpInfoProvider::new();
            let resp = ipinfo_result.get_info(&target_ip).await;
            match resp {
                Ok(info) => {
                    let provider = String::from("ipinfo.com");
                    let country_code = info.country.unwrap_or_default();
                    let city = info.city.unwrap_or_default();
                    let as_number = info.org.unwrap_or_default();
                    let as_name = String::new();
                    let reverse = info.hostname.unwrap_or_default();

                    geo_info.push(GeoInfo {
                        provider,
                        country_code,
                        city,
                        as_number,
                        as_name,
                        reverse,
                    })
                },
                Err(_) => {}
            }
        }

        if config.ipinfo_providers.contains(&String::from("ipwho.is")) {
            let ipwhois_result = ipinfo_providers::ipwho_is::IpWhoIsProvider::new();
            let resp = ipwhois_result.get_info(&target_ip).await;
            match resp {
                Ok(info) => {
                    let provider = String::from("ipwho.is");
                    let country_code = info.country_code.unwrap_or_default();
                    let city = info.city.unwrap_or_default();
                    let as_number = format!("AS{} {}", info.asn.unwrap_or_default(), info.isp.unwrap_or_default());
                    let as_name = String::new();
                    let reverse = info.domain.unwrap_or_default();

                    geo_info.push(GeoInfo {
                        provider,
                        country_code,
                        city,
                        as_number,
                        as_name,
                        reverse,
                    })
                },
                Err(_) => {}
            }
        }

        if config.ipinfo_providers.contains(&String::from("ip.sb")) {
            let ipsb_result = ipinfo_providers::ip_sb::IpSbProvider::new();
            let resp = ipsb_result.get_info(&target_ip).await;
            match resp {
                Ok(info) => {
                    let provider = String::from("ip.sb");
                    let country_code = info.country_code.unwrap_or_default();
                    let city = info.city.unwrap_or_default();
                    let as_number = format!("AS{} {}", info.asn.unwrap_or_default(), info.asn_organization.unwrap_or_default());
                    let as_name = String::new();
                    let reverse = String::new();

                    geo_info.push(GeoInfo {
                        provider,
                        country_code,
                        city,
                        as_number,
                        as_name,
                        reverse,
                    })
                },
                Err(_) => {}
            }
        }

        if config.ipinfo_providers.contains(&String::from("ipapi.co")) {
            let ipapi_co_result = ipinfo_providers::ipapi_co::IpApiCoProvider::new();
            let resp = ipapi_co_result.get_info(&target_ip).await;
            match resp {
                Ok(info) => {
                    let provider = String::from("ipapi.co");
                    let country_code = info.country_code.unwrap_or_default();
                    let city = info.city.unwrap_or_default();
                    let as_number = format!("{} {}", info.asn.unwrap_or_default(), info.org.unwrap_or_default());
                    let as_name = String::new();
                    let reverse = info.network.unwrap_or_default();

                    geo_info.push(GeoInfo {
                        provider,
                        country_code,
                        city,
                        as_number,
                        as_name,
                        reverse,
                    });
                },
                Err(e) => {
                    println!("ERR {}", e);
                }
            }
        }

        if config.ipinfo_providers.contains(&String::from("GeoIP")) {
            let geoip = GeoIpService::new(
                &config.geoip_city_db.as_ref().unwrap(),
                &config.geoip_asn_db.as_ref().unwrap(),
            )?;
            let info = geoip.get_ip_info(target_ip.parse()?)?;

            let provider = String::from("GeoIP");
            let country_code = info.country;
            let city = info.city;
            let as_number = format!("AS{} {}", info.asn, info.as_name);
            let as_name = String::new();
            let reverse = String::new();

            geo_info.push(GeoInfo {
                provider,
                country_code,
                city,
                as_number,
                as_name,
                reverse,
            });
        }

        let w1 = geo_info.iter().map(|info| info.provider.len()).max().unwrap_or(0);
        let w2 = geo_info.iter().map(|info| info.country_code.len()).max().unwrap_or(0);
        let w3 = geo_info.iter().map(|info| info.city.len()).max().unwrap_or(0);
        let w4 = geo_info.iter().map(|info| info.as_number.len()).max().unwrap_or(0);
        let w5 = geo_info.iter().map(|info| info.as_name.len()).max().unwrap_or(0);
        let w6 = geo_info.iter().map(|info| info.reverse.len()).max().unwrap_or(0);

        let w99 = w1 + w2 + w3 + w4 + w5 + w6 + 15;

        for (i, info) in geo_info.iter().enumerate() {
            if i < 2 {
                println!("{}", "─".repeat(w99));
            }
            println!(
                "{:<w1$} | {:<w2$} | {:<w3$} | {:<w4$} | {:<w5$} | {:<w6$}",
                info.provider, info.country_code, info.city, info.as_number, info.as_name, info.reverse
            );
        };
    } else {
        println!("No providers specified for IP info");
    }

    Ok(())
}