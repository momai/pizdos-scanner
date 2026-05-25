use std::{collections::HashSet, sync::Arc};

use colored::*;
use ipnetwork::Ipv4Network;
use tokio::{sync::Semaphore, task::JoinSet, time::Instant};

use crate::{
    geoip::{GeoIpService, SubnetInfo},
    icmp::ProbeTuning,
    init::{Config, ConfigSocketType},
    scan_state::{save_state_snapshot, ScanProgress, ScanState},
    scanner::{
        scan_conditions::{
            check_endpoint_with_retries, graceful_stop_on_available, handle_endpoint_failure,
            handle_periodic_stop_action, probe_stop_target, StopProbeResult, StopTargetChecker,
        },
        scan_loop::SubnetIterationOutcome,
    },
    tui::{EventLevel, ScanUi},
    utils::SubnetProbeStats,
};

struct ParallelSubnetOutcome {
    index: usize,
    subnet: Ipv4Network,
    elapsed_sec: f64,
    result: anyhow::Result<(Ipv4Network, SubnetInfo, SubnetProbeStats)>,
}

fn apply_parallel_outcome(
    outcome: ParallelSubnetOutcome,
    ui: &mut Option<ScanUi>,
    scan_progress: &ScanProgress,
    state: &ScanState,
    completed_subnets: &mut HashSet<String>,
    failed_subnets: &mut HashSet<String>,
    processed_networks: &mut Vec<(Ipv4Network, SubnetInfo, SubnetProbeStats)>,
    scanned_this_run: &mut usize,
) -> anyhow::Result<()> {
    let subnet_string = outcome.subnet.to_string();
    match outcome.result {
        Ok(result) => {
            let stats = &result.2;
            let rejected = stats
                .hosts
                .iter()
                .filter(|host| !host.tcp_rejected_ports.is_empty())
                .count();

            if let Some(ui) = ui.as_ref() {
                ui.complete_subnet(
                    outcome.index + 1,
                    &subnet_string,
                    stats.icmp_alive,
                    stats.tcp_alive,
                    rejected,
                    outcome.elapsed_sec,
                );
            } else if scan_progress.is_active() {
                let summary = if stats.tcp_alive > 0 || stats.icmp_alive > 0 {
                    format!(
                        "{} icmp {} tcp {} {:.1}s",
                        subnet_string, stats.icmp_alive, stats.tcp_alive, outcome.elapsed_sec
                    )
                } else {
                    format!("{subnet_string} dead {:.1}s", outcome.elapsed_sec)
                };
                scan_progress.set_message(summary);
            }

            crate::utils::append_result_to_csv(&result, &state.result_csv)?;
            crate::utils::append_result_to_jsonl(&result, &state.result_jsonl)?;
            crate::utils::append_result_to_txt_lists(
                &result,
                &state.result_alive_txt,
                &state.result_rejected_txt,
            )?;
            processed_networks.push(result);
            completed_subnets.insert(subnet_string.clone());
            failed_subnets.remove(&subnet_string);
            *scanned_this_run += 1;
            scan_progress.complete_subnet();
        }
        Err(e) => {
            if let Some(ui) = ui.as_ref() {
                ui.subnet_error(outcome.index + 1, &subnet_string, &e.to_string());
            } else {
                eprintln!("{}", format!("  error {subnet_string}: {e}").red());
            }
            failed_subnets.insert(subnet_string.clone());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_parallel_subnets(
    config: &Config,
    all_subnets: &[Ipv4Network],
    geoip: Option<GeoIpService>,
    source: String,
    fallback_country: Option<String>,
    tcp_ports: Vec<u16>,
    tcp_sni_host: Option<String>,
    network_interface: Option<String>,
    socket_type: ConfigSocketType,
    tuning: ProbeTuning,
    state_path: &std::path::Path,
    state: &mut ScanState,
    ui: &mut Option<ScanUi>,
    stop_checker: &mut Option<StopTargetChecker>,
    host_probe_semaphore: Arc<Semaphore>,
    scan_progress: &ScanProgress,
    completed_subnets: &mut HashSet<String>,
    failed_subnets: &mut HashSet<String>,
    processed_networks: &mut Vec<(Ipv4Network, SubnetInfo, SubnetProbeStats)>,
    scanned_this_run: &mut usize,
    stop_every: u32,
) -> anyhow::Result<SubnetIterationOutcome> {
    let already_done = completed_subnets.clone();
    let ping_type = config.ping_type.clone();
    let pending: Vec<(usize, Ipv4Network)> = all_subnets
        .iter()
        .enumerate()
        .filter(|(_, subnet)| !already_done.contains(&subnet.to_string()))
        .map(|(idx, subnet)| (idx, *subnet))
        .collect();

    let mut join_set: JoinSet<ParallelSubnetOutcome> = JoinSet::new();
    let parallelism = config.subnet_parallelism();
    let mut next = 0usize;
    let mut pending_batch: Vec<ParallelSubnetOutcome> = Vec::new();

    while next < pending.len() && join_set.len() < parallelism {
        if let Some(checker) = stop_checker {
            match probe_stop_target(checker, ui.as_ref(), network_interface.as_deref(), false) {
                StopProbeResult::Interrupted => return Ok(SubnetIterationOutcome::Interrupted),
                StopProbeResult::ContinueAvailable if checker.stop.check_before_subnet => {
                    graceful_stop_on_available(state_path, state, &checker.stop, None, ui.as_ref())?;
                    return Ok(SubnetIterationOutcome::Stopped);
                }
                StopProbeResult::ContinueAvailable | StopProbeResult::ContinueUnavailable => {}
            }
        }

        let (index, subnet24) = pending[next];
        next += 1;
        if let Some(ui_ref) = ui.as_ref() {
            ui_ref.set_scanning(index + 1, &subnet24.to_string());
        }
        join_set.spawn({
            let source = source.clone();
            let fallback_country = fallback_country.clone();
            let ping_type = ping_type.clone();
            let tcp_ports = tcp_ports.clone();
            let tcp_sni_host = tcp_sni_host.clone();
            let network_interface = network_interface.clone();
            let geoip = geoip.clone();
            let socket_type = socket_type.clone();
            let host_probe_semaphore = Arc::clone(&host_probe_semaphore);
            async move {
                let started = Instant::now();
                let result = crate::icmp::process_subnet(
                    subnet24,
                    geoip.as_ref(),
                    &source,
                    fallback_country.as_deref(),
                    Arc::clone(&host_probe_semaphore),
                    tuning,
                    &socket_type,
                    &ping_type,
                    &tcp_ports,
                    tcp_sni_host.as_deref(),
                    network_interface.as_deref(),
                )
                .await;
                ParallelSubnetOutcome {
                    index,
                    subnet: subnet24,
                    elapsed_sec: started.elapsed().as_secs_f64(),
                    result,
                }
            }
        });
        if let Some(ui_ref) = ui.as_ref() {
            ui_ref.set_inflight_subnets(join_set.len());
        }
    }

    while let Some(joined) = join_set.join_next().await {
        if ui.as_ref().is_some_and(ScanUi::cancelled) {
            join_set.abort_all();
            return Ok(SubnetIterationOutcome::Interrupted);
        }

        let outcome = match joined {
            Ok(outcome) => outcome,
            Err(e) => anyhow::bail!("parallel worker failed: {e}"),
        };
        if let Some(ui_ref) = ui.as_ref() {
            ui_ref.set_inflight_subnets(join_set.len());
        }

        if outcome.result.is_ok() {
            let subnet_string = outcome.subnet.to_string();
            if let Some(checker) = stop_checker {
                match probe_stop_target(checker, ui.as_ref(), network_interface.as_deref(), false) {
                    StopProbeResult::Interrupted => {
                        join_set.abort_all();
                        return Ok(SubnetIterationOutcome::Interrupted);
                    }
                    StopProbeResult::ContinueAvailable if checker.stop.check_after_subnet => {
                        graceful_stop_on_available(
                            state_path,
                            state,
                            &checker.stop,
                            Some(&subnet_string),
                            ui.as_ref(),
                        )?;
                        join_set.abort_all();
                        return Ok(SubnetIterationOutcome::Stopped);
                    }
                    StopProbeResult::ContinueAvailable | StopProbeResult::ContinueUnavailable => {}
                }
            }
        }

        pending_batch.push(outcome);
        let need_endpoint_check =
            pending_batch.len() >= parallelism || (next >= pending.len() && join_set.is_empty());

        if need_endpoint_check {
            let endpoint = &config.endpoint;
            let (endpoint_available, endpoint_interrupted) = check_endpoint_with_retries(
                endpoint,
                &socket_type,
                network_interface.as_deref(),
                ui.as_ref(),
            )
            .await;
            if endpoint_interrupted {
                join_set.abort_all();
                return Ok(SubnetIterationOutcome::Interrupted);
            }
            if !endpoint_available {
                let dropped = pending_batch.len();
                pending_batch.clear();
                handle_endpoint_failure(
                    config,
                    endpoint,
                    network_interface.as_deref(),
                    state_path,
                    state,
                    ui,
                )
                .await?;
                if dropped > 0 {
                    let msg = format!("discarded {dropped} subnet(s): endpoint became unavailable");
                    if let Some(ui) = ui.as_ref() {
                        ui.log(EventLevel::Wrn, msg);
                    } else {
                        eprintln!("{}", msg.yellow());
                    }
                }
                continue;
            }

            for item in pending_batch.drain(..) {
                apply_parallel_outcome(
                    item,
                    ui,
                    scan_progress,
                    state,
                    completed_subnets,
                    failed_subnets,
                    processed_networks,
                    scanned_this_run,
                )?;
                save_state_snapshot(state_path, state, completed_subnets, failed_subnets)?;
                if stop_every != 0 && state.subnet24_count % stop_every == 0 {
                    handle_periodic_stop_action(config, ui.as_ref()).await?;
                }
            }
        }

        while next < pending.len() && join_set.len() < parallelism && !ui.as_ref().is_some_and(ScanUi::cancelled) {
            if let Some(checker) = stop_checker {
                match probe_stop_target(checker, ui.as_ref(), network_interface.as_deref(), false) {
                    StopProbeResult::Interrupted => {
                        join_set.abort_all();
                        return Ok(SubnetIterationOutcome::Interrupted);
                    }
                    StopProbeResult::ContinueAvailable if checker.stop.check_before_subnet => {
                        graceful_stop_on_available(state_path, state, &checker.stop, None, ui.as_ref())?;
                        join_set.abort_all();
                        return Ok(SubnetIterationOutcome::Stopped);
                    }
                    StopProbeResult::ContinueAvailable | StopProbeResult::ContinueUnavailable => {}
                }
            }

            let (index, subnet24) = pending[next];
            next += 1;
            if let Some(ui_ref) = ui.as_ref() {
                ui_ref.set_scanning(index + 1, &subnet24.to_string());
            }
            join_set.spawn({
                let source = source.clone();
                let fallback_country = fallback_country.clone();
                let ping_type = ping_type.clone();
                let tcp_ports = tcp_ports.clone();
                let tcp_sni_host = tcp_sni_host.clone();
                let network_interface = network_interface.clone();
                let geoip = geoip.clone();
                let socket_type = socket_type.clone();
                let host_probe_semaphore = Arc::clone(&host_probe_semaphore);
                async move {
                    let started = Instant::now();
                    let result = crate::icmp::process_subnet(
                        subnet24,
                        geoip.as_ref(),
                        &source,
                        fallback_country.as_deref(),
                        Arc::clone(&host_probe_semaphore),
                        tuning,
                        &socket_type,
                        &ping_type,
                        &tcp_ports,
                        tcp_sni_host.as_deref(),
                        network_interface.as_deref(),
                    )
                    .await;
                    ParallelSubnetOutcome {
                        index,
                        subnet: subnet24,
                        elapsed_sec: started.elapsed().as_secs_f64(),
                        result,
                    }
                }
            });
            if let Some(ui_ref) = ui.as_ref() {
                ui_ref.set_inflight_subnets(join_set.len());
            }
        }
    }

    Ok(SubnetIterationOutcome::Continue)
}
