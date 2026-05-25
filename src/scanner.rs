mod scan_conditions;
mod scan_loop;
mod parallel;

use anyhow::Context;
use colored::*;
use ipnetwork::Ipv4Network;
use std::{collections::HashSet, sync::Arc, time::{Duration, Instant}};
use tokio::sync::Semaphore;

use crate::geoip::{GeoIpService, SubnetInfo};
use crate::icmp::{probe_host, split_ipv4_to_24, ProbeTuning};
use crate::init::{Config, ConfigPingType, ConfigSaveResultFileType, ConfigSocketType};
use crate::scan_state::{
    build_job_id, create_state, load_state, save_state, state_path, ScanProgress, SessionSummary,
};
use crate::scanner::scan_conditions::{init_scan_ui, StopTargetChecker};
use crate::scanner::scan_loop::{
    process_subnet_iteration, SubnetIterationCtx, SubnetIterationOutcome,
};
use crate::scanner::parallel::run_parallel_subnets;
use crate::tui::{EventLevel, ScanUi};
use crate::utils::{is_cidr_line, save_results_to_file, save_results_to_json, SubnetProbeStats};

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

fn format_elapsed(elapsed: Duration) -> String {
    let total = elapsed.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        total / 3600,
        (total % 3600) / 60,
        total % 60
    )
}

fn build_session_summary(scanned_this_run: usize, elapsed: Duration, workers: usize) -> SessionSummary {
    let workers = workers.max(1);
    let elapsed_secs = elapsed.as_secs_f64();
    if scanned_this_run == 0 || elapsed_secs <= 0.0 {
        return SessionSummary {
            scanned_this_run,
            elapsed_seconds: elapsed_secs,
            workers,
            rate_total_per_min: 0.0,
            rate_per_worker_per_min: 0.0,
            avg_seconds_per_subnet: 0.0,
            finished_at: chrono::Local::now().to_rfc3339(),
        };
    }

    let rate_total_per_min = scanned_this_run as f64 / elapsed_secs * 60.0;
    let rate_per_worker_per_min = rate_total_per_min / workers as f64;
    let avg_seconds_per_subnet = elapsed_secs / scanned_this_run as f64;
    SessionSummary {
        scanned_this_run,
        elapsed_seconds: elapsed_secs,
        workers,
        rate_total_per_min,
        rate_per_worker_per_min,
        avg_seconds_per_subnet,
        finished_at: chrono::Local::now().to_rfc3339(),
    }
}

fn render_session_report(
    status: &str,
    scanned_this_run: usize,
    total_done: usize,
    result_path: &str,
    summary: &SessionSummary,
    previous: Option<&SessionSummary>,
) -> String {
    let finished = status == "Готово";
    let badge = if finished {
        " ГОТОВО ".black().on_green().bold().to_string()
    } else {
        " СТОП ".black().on_yellow().bold().to_string()
    };

    let sep = "─".repeat(46).bright_black().to_string();

    // Line 1: status + counts
    let counts = format!(
        "всего: {}  •  эта сессия: {}  •  воркеры: {}  •  {}",
        total_done.to_string().bold(),
        scanned_this_run.to_string().bold(),
        summary.workers.to_string().bold(),
        format_elapsed(Duration::from_secs_f64(summary.elapsed_seconds.max(0.0))).bold(),
    );

    // Line 2: speed stats for this session (only if scanned > 0)
    let speed_line = if summary.scanned_this_run > 0 {
        format!(
            "  {}  {:.2}/мин  •  {:.1}с/подсеть",
            "↗ скорость:".bright_cyan(),
            summary.rate_total_per_min,
            summary.avg_seconds_per_subnet
        )
    } else {
        format!("  {}", "↗ скорость: нет данных (0 подсетей за сессию)".bright_black())
    };

    // Line 3: comparison
    let compare_line = match previous {
        Some(prev) if prev.rate_total_per_min > 0.0 && summary.rate_total_per_min > 0.0 => {
            let speedup = summary.rate_total_per_min / prev.rate_total_per_min;
            let delta_pct = (speedup - 1.0) * 100.0;
            let (marker, cmp_str) = if delta_pct >= 1.0 {
                ("↑", format!("x{:.2} ({:+.0}%) — быстрее (пред. {:.2}/мин, {}w)", speedup, delta_pct, prev.rate_total_per_min, prev.workers).green().bold().to_string())
            } else if delta_pct <= -1.0 {
                ("↓", format!("x{:.2} ({:+.0}%) — медленнее (пред. {:.2}/мин, {}w)", speedup, delta_pct, prev.rate_total_per_min, prev.workers).yellow().bold().to_string())
            } else {
                ("≈", format!("примерно одинаково с предыдущей (пред. {:.2}/мин, {}w)", prev.rate_total_per_min, prev.workers).bright_black().to_string())
            };
            format!("  {}  {}", marker.bright_magenta().bold(), cmp_str)
        }
        Some(_) => format!("  {}", "≈ сравнение: недостаточно данных".bright_black()),
        None    => format!("  {}", "≈ первый запуск, сравнение пока недоступно".bright_black()),
    };

    // Line 4: file path
    let file_line = format!(
        "  {}  {}",
        "📄".bright_black(),
        result_path.bright_white()
    );

    format!("{sep}\n{badge}  {counts}\n{speed_line}\n{compare_line}\n{file_line}\n{sep}")
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
    let session_started_at = Instant::now();
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
    let previous_session = state.last_session.clone();
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
    let subnet_parallelism = config.subnet_parallelism();

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
    let host_probe_limit = config.host_probe_parallelism();
    let host_probe_semaphore = Arc::new(Semaphore::new(host_probe_limit));
    let scan_progress = ScanProgress::new(ui.is_none(), all_subnets.len(), completed_subnets.len());
    if let Some(ui) = ui.as_ref() {
        let mode = if config.host_probe_parallelism.is_some() {
            "manual"
        } else {
            "auto"
        };
        ui.log(
            EventLevel::Inf,
            format!("Host-probe limit: {host_probe_limit} ({mode})"),
        );
    } else {
        let mode = if config.host_probe_parallelism.is_some() {
            "manual"
        } else {
            "auto"
        };
        println!(
            "{}",
            format!("host-probe limit: {host_probe_limit} ({mode})").dimmed()
        );
    }
    if subnet_parallelism > 1 {
        if let Some(ui) = ui.as_ref() {
            ui.log(
                EventLevel::Inf,
                format!("Subnet parallelism: {subnet_parallelism} workers"),
            );
        } else {
            println!("{}", format!("parallel mode: {subnet_parallelism} /24 workers").cyan());
        }
        match run_parallel_subnets(
            config,
            &all_subnets,
            geoip.clone(),
            source.clone(),
            fallback_country.clone(),
            tcp_ports.clone(),
            tcp_sni_host.map(|s| s.to_string()),
            network_interface.map(|s| s.to_string()),
            socket_type.clone(),
            ProbeTuning::from_config(config),
            &state_path,
            &mut state,
            &mut ui,
            &mut stop_checker,
            Arc::clone(&host_probe_semaphore),
            &scan_progress,
            &mut completed_subnets,
            &mut failed_subnets,
            &mut processed_networks,
            &mut scanned_this_run,
            stop_every,
        )
        .await?
        {
            SubnetIterationOutcome::Continue => {}
            SubnetIterationOutcome::Interrupted => interrupted = true,
            SubnetIterationOutcome::Stopped => return Ok(()),
        }
    } else {
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
                host_probe_semaphore: &host_probe_semaphore,
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
    }

    if interrupted {
        let session_summary = build_session_summary(
            scanned_this_run,
            session_started_at.elapsed(),
            subnet_parallelism,
        );
        state.last_session = Some(session_summary.clone());
        save_state(&state_path, &mut state)?;
        let msg = render_session_report(
            "Остановлено",
            scanned_this_run,
            completed_subnets.len(),
            &state.result_jsonl,
            &session_summary,
            previous_session.as_ref(),
        );
        if let Some(ui) = ui.take() {
            ui.log(EventLevel::Wrn, "Остановлено пользователем");
            ui.finish(msg);
        } else {
            println!("{msg}");
        }
        return Ok(());
    }

    state.finished = true;
    state.stopped_reason = None;
    let session_summary = build_session_summary(
        scanned_this_run,
        session_started_at.elapsed(),
        subnet_parallelism,
    );
    state.last_session = Some(session_summary.clone());
    save_state(&state_path, &mut state)?;

    let done_msg = render_session_report(
        "Готово",
        scanned_this_run,
        completed_subnets.len(),
        &state.result_jsonl,
        &session_summary,
        previous_session.as_ref(),
    );

    if let Some(ui) = ui {
        ui.log(EventLevel::Ok, "Скан завершён");
        ui.finish(done_msg);
    } else {
        println!("{done_msg}");
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
