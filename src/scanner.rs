mod scan_conditions;
mod scan_loop;

use anyhow::Context;
use colored::*;
use ipnetwork::Ipv4Network;
use std::collections::HashSet;

use crate::geoip::{GeoIpService, SubnetInfo};
use crate::icmp::{probe_host, split_ipv4_to_24, ProbeTuning};
use crate::init::{Config, ConfigPingType, ConfigSaveResultFileType, ConfigSocketType};
use crate::scan_state::{
    build_job_id, create_state, load_state, save_state, state_path, ScanProgress,
};
use crate::scanner::scan_conditions::{init_scan_ui, StopTargetChecker};
use crate::scanner::scan_loop::{
    process_subnet_iteration, SubnetIterationCtx, SubnetIterationOutcome,
};
use crate::tui::{EventLevel, ScanUi};
use crate::utils::{save_results_to_file, save_results_to_json, is_cidr_line, SubnetProbeStats};

fn scan_source(scan_name: &str) -> String {
    scan_name
        .strip_prefix("geoip_")
        .unwrap_or(scan_name)
        .replace('_', ",")
        .to_uppercase()
}

fn fallback_country_for_source(source: &str) -> Option<String> {
    if source.len() == 2 && source.chars().all(|ch| ch.is_ascii_alphabetic()) {
        Some(source.to_string())
    } else {
        None
    }
}

fn icmp_unavailable_hint(socket_type: &ConfigSocketType) -> &'static str {
    match socket_type {
        ConfigSocketType::DGRAM => {
            "ICMP через DGRAM сейчас недоступен для текущего пользователя.\n\
             Для Linux без sudo выполните:\n\
               sudo sysctl -w net.ipv4.ping_group_range=\"0 1000\"\n\
             (постоянно: добавьте net.ipv4.ping_group_range = 0 1000 в /etc/sysctl.d/*.conf и примените sysctl --system)\n\
             Либо используйте socket_type = \"RAW\" (нужны CAP_NET_RAW/root) или ping_type = [\"TCP\"]."
        }
        ConfigSocketType::RAW => {
            "ICMP через RAW недоступен: нужен CAP_NET_RAW или запуск от root.\n\
             Либо используйте ping_type = [\"TCP\"]."
        }
    }
}

fn expand_to_24(networks: &[String]) -> anyhow::Result<Vec<Ipv4Network>> {
    let mut seen = HashSet::new();
    let mut expanded = Vec::new();

    for network in networks {
        if !is_cidr_line(network) {
            continue;
        }
        let ip_net: Ipv4Network = network
            .trim()
            .parse()
            .with_context(|| format!("Failed to parse network {}", network))?;
        for subnet in split_ipv4_to_24(ip_net)? {
            let key = (u32::from(subnet.network()), subnet.prefix());
            if seen.insert(key) {
                expanded.push(subnet);
            }
        }
    }

    expanded.sort_by_key(|network| (u32::from(network.network()), network.prefix()));
    Ok(expanded)
}

pub async fn scan_networks(
    config: &Config,
    scan_name: &str,
    networks: Vec<String>,
) -> anyhow::Result<()> {
    let geoip = match GeoIpService::new(
        &config.geoip_city_db.as_ref().unwrap(),
        &config.geoip_asn_db.as_ref().unwrap(),
    ) {
        Ok(geoip) => Some(geoip),
        Err(e) => {
            eprintln!("⚠️ GeoIP mmdb unavailable, scan results will use N/A geo fields: {}", e);
            None
        }
    };

    if config.ping_type.contains(&ConfigPingType::ICMP) {
        let socket_type = config
            .socket_type
            .as_ref()
            .context("socket_type is required when ICMP is enabled")?;
        let tuning = ProbeTuning::from_config(config);
        if !probe_host(
            "127.0.0.1".parse()?,
            1,
            tuning.icmp_timeout,
            tuning.icmp_retry_delay,
            tuning.tcp_timeout,
            socket_type,
            &vec![ConfigPingType::ICMP],
            &[],
            None,
            None,
        )
        .icmp
        {
            anyhow::bail!(
                "Preflight check failed before scan start: ICMP not available for socket_type={socket_type:?}.\n{}",
                icmp_unavailable_hint(socket_type)
            );
        }
    }

    let mut processed_networks: Vec<(Ipv4Network, SubnetInfo, SubnetProbeStats)> = Vec::new();
    let endpoint = config.endpoint.clone();
    let tcp_ports = config.tcp_ports();
    let tcp_sni_host = config.tcp_sni_host.as_deref();
    let network_interface = config.network_interface();
    let source = scan_source(scan_name);
    let fallback_country = fallback_country_for_source(&source);
    let all_subnets = expand_to_24(&networks)?;
    let job_id = build_job_id(config, scan_name, &networks);
    let state_path = state_path(config, &job_id);
    let mut state = match (config.resume_enabled(), load_state(&state_path)?) {
        (true, Some(state)) if !state.finished => state,
        _ => create_state(config, scan_name, job_id),
    };
    save_state(&state_path, &mut state)?;

    let mut completed_subnets: HashSet<String> = state.completed_subnets.iter().cloned().collect();
    let mut failed_subnets: HashSet<String> = state.failed_subnets.iter().cloned().collect();
    let stop_every = if config.task.is_some() {
        config.task.as_ref().unwrap().stop_every_times
    } else {
        0
    };
    let mut stop_checker = config
        .stop_on_available
        .as_ref()
        .filter(|stop| stop.is_active())
        .cloned()
        .map(StopTargetChecker::new);

    let whitelist_label = stop_checker.as_ref().map(|c| c.label());
    let mut ui: Option<ScanUi> = init_scan_ui(
        config,
        scan_name,
        all_subnets.len(),
        completed_subnets.len(),
        &endpoint,
        whitelist_label.as_deref(),
        &tcp_ports,
        &state,
    )?;
    let socket_type = config
        .socket_type
        .as_ref()
        .context("socket_type is required")?;

    let mut scanned_this_run = 0usize;
    let mut interrupted = false;
    let scan_progress = ScanProgress::new(ui.is_none(), all_subnets.len(), completed_subnets.len());

    for (index, subnet24) in all_subnets.iter().enumerate() {
        if ui.as_ref().is_some_and(ScanUi::cancelled) {
            interrupted = true;
            break;
        }

        if completed_subnets.contains(&subnet24.to_string()) {
            continue;
        }

        match process_subnet_iteration(SubnetIterationCtx {
            config,
            subnet24: *subnet24,
            index,
            geoip: geoip.as_ref(),
            source: &source,
            fallback_country: fallback_country.as_deref(),
            tcp_ports: &tcp_ports,
            tcp_sni_host,
            network_interface,
            endpoint: &endpoint,
            socket_type,
            state_path: &state_path,
            state: &mut state,
            stop_checker: &mut stop_checker,
            ui: &mut ui,
            scan_progress: &scan_progress,
            completed_subnets: &mut completed_subnets,
            failed_subnets: &mut failed_subnets,
            processed_networks: &mut processed_networks,
            scanned_this_run: &mut scanned_this_run,
            stop_every,
        })
        .await?
        {
            SubnetIterationOutcome::Continue => {}
            SubnetIterationOutcome::Interrupted => {
                interrupted = true;
                break;
            }
            SubnetIterationOutcome::Stopped => return Ok(()),
        }
    }

    if interrupted {
        save_state(&state_path, &mut state)?;
        let msg = format!(
            "interrupted: {} /24 this run, {} total · resume: {}",
            scanned_this_run,
            completed_subnets.len(),
            state.result_jsonl
        );
        if let Some(ui) = ui.take() {
            ui.log(EventLevel::Wrn, "Остановлено пользователем");
            ui.finish(msg);
        } else {
            println!("{}", msg.yellow());
        }
        return Ok(());
    }

    state.finished = true;
    state.stopped_reason = None;
    save_state(&state_path, &mut state)?;

    let done_msg = format!(
        "done: {} /24 this run, {} total · {}",
        scanned_this_run,
        completed_subnets.len(),
        state.result_jsonl
    );

    if let Some(ui) = ui {
        ui.log(EventLevel::Ok, "Скан завершён");
        ui.finish(done_msg);
    } else {
        println!("{}", done_msg.cyan());
    }

    if !config.logger_filetype.is_empty() {
        let result_path = std::path::PathBuf::from(config.results_dir());

        if config
            .logger_filetype
            .contains(&ConfigSaveResultFileType::Csv)
        {
            let csv = result_path.join(format!("{}_final.csv", state.job_id));
            let csv = csv.to_string_lossy().to_string();
            let _ = save_results_to_file(&processed_networks.clone(), &csv);
        }
        if config
            .logger_filetype
            .contains(&ConfigSaveResultFileType::Json)
        {
            let json = result_path.join(format!("{}_final.json", state.job_id));
            let json = json.to_string_lossy().to_string();
            let _ = save_results_to_json(&processed_networks.clone(), &json);
        }
    }
    Ok(())
}
