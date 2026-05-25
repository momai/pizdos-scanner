use colored::*;
use ipnetwork::Ipv4Network;
use std::{collections::HashSet, path::Path, sync::Arc};
use tokio::time::Instant;
use tokio::sync::Semaphore;

use crate::geoip::{GeoIpService, SubnetInfo};
use crate::icmp::{process_subnet, ProbeTuning};
use crate::init::{Config, ConfigSocketType};
use crate::scan_state::{save_state_snapshot, ScanProgress, ScanState};
use crate::scanner::scan_conditions::{
    check_endpoint_with_retries, graceful_stop_on_available, handle_endpoint_failure,
    handle_periodic_stop_action, probe_stop_target, StopProbeResult, StopTargetChecker,
};
use crate::tui::{EventLevel, ScanUi};
use crate::utils::{
    append_result_to_csv, append_result_to_jsonl, append_result_to_txt_lists, SubnetProbeStats,
};

fn count_rejected_hosts(stats: &SubnetProbeStats) -> usize {
    stats
        .hosts
        .iter()
        .filter(|host| !host.tcp_rejected_ports.is_empty())
        .count()
}

pub(crate) enum SubnetIterationOutcome {
    Continue,
    Interrupted,
    Stopped,
}

pub(crate) struct SubnetIterationCtx<'a> {
    pub(crate) config: &'a Config,
    pub(crate) subnet24: Ipv4Network,
    pub(crate) index: usize,
    pub(crate) geoip: Option<&'a GeoIpService>,
    pub(crate) source: &'a str,
    pub(crate) fallback_country: Option<&'a str>,
    pub(crate) tcp_ports: &'a [u16],
    pub(crate) tcp_sni_host: Option<&'a str>,
    pub(crate) network_interface: Option<&'a str>,
    pub(crate) endpoint: &'a str,
    pub(crate) socket_type: &'a ConfigSocketType,
    pub(crate) state_path: &'a Path,
    pub(crate) state: &'a mut ScanState,
    pub(crate) stop_checker: &'a mut Option<StopTargetChecker>,
    pub(crate) host_probe_semaphore: &'a Arc<Semaphore>,
    pub(crate) ui: &'a mut Option<ScanUi>,
    pub(crate) scan_progress: &'a ScanProgress,
    pub(crate) completed_subnets: &'a mut HashSet<String>,
    pub(crate) failed_subnets: &'a mut HashSet<String>,
    pub(crate) processed_networks: &'a mut Vec<(Ipv4Network, SubnetInfo, SubnetProbeStats)>,
    pub(crate) scanned_this_run: &'a mut usize,
    pub(crate) stop_every: u32,
}

pub(crate) async fn process_subnet_iteration(
    ctx: SubnetIterationCtx<'_>,
) -> anyhow::Result<SubnetIterationOutcome> {
    let SubnetIterationCtx {
        config,
        subnet24,
        index,
        geoip,
        source,
        fallback_country,
        tcp_ports,
        tcp_sni_host,
        network_interface,
        endpoint,
        socket_type,
        state_path,
        state,
        stop_checker,
        host_probe_semaphore,
        ui,
        scan_progress,
        completed_subnets,
        failed_subnets,
        processed_networks,
        scanned_this_run,
        stop_every,
    } = ctx;

    let subnet_string = subnet24.to_string();

    if let Some(checker) = stop_checker {
        if ui.as_ref().is_some_and(ScanUi::cancelled) {
            return Ok(SubnetIterationOutcome::Interrupted);
        }
        match probe_stop_target(checker, ui.as_ref(), network_interface, true) {
            StopProbeResult::Interrupted => return Ok(SubnetIterationOutcome::Interrupted),
            StopProbeResult::ContinueAvailable => {
                if checker.stop.check_before_subnet {
                    graceful_stop_on_available(state_path, state, &checker.stop, None, ui.as_ref())?;
                    if let Some(ui) = ui.take() {
                        ui.finish(format!(
                            "stopped: whitelist · {} /24 this run",
                            scanned_this_run
                        ));
                    }
                    return Ok(SubnetIterationOutcome::Stopped);
                }
            }
            StopProbeResult::ContinueUnavailable => {}
        }
    }

    let done_before = completed_subnets.len() + *scanned_this_run;
    if let Some(ui) = ui.as_ref() {
        ui.set_scanning(index + 1, &subnet_string);
    } else {
        scan_progress.set_position(done_before, &subnet_string);
    }

    let iteration_start = Instant::now();
    match process_subnet(
        subnet24,
        geoip,
        source,
        fallback_country,
        Arc::clone(host_probe_semaphore),
        ProbeTuning::from_config(config),
        config.socket_type.as_ref().unwrap(),
        &config.ping_type,
        tcp_ports,
        tcp_sni_host,
        network_interface,
    )
    .await
    {
        Ok(result) => {
            let iteration_time = iteration_start.elapsed();
            let stats = &result.2;
            let elapsed_sec = iteration_time.as_secs_f64();
            let rejected = count_rejected_hosts(stats);

            if let Some(checker) = stop_checker {
                if ui.as_ref().is_some_and(ScanUi::cancelled) {
                    return Ok(SubnetIterationOutcome::Interrupted);
                }
                match probe_stop_target(checker, ui.as_ref(), network_interface, false) {
                    StopProbeResult::Interrupted => return Ok(SubnetIterationOutcome::Interrupted),
                    StopProbeResult::ContinueAvailable => {
                        if checker.stop.check_after_subnet {
                            graceful_stop_on_available(
                                state_path,
                                state,
                                &checker.stop,
                                Some(&subnet_string),
                                ui.as_ref(),
                            )?;
                            if let Some(ui) = ui.take() {
                                ui.finish(format!(
                                    "stopped: whitelist · {} /24 this run",
                                    scanned_this_run
                                ));
                            }
                            return Ok(SubnetIterationOutcome::Stopped);
                        }
                    }
                    StopProbeResult::ContinueUnavailable => {}
                }
            }

            let (endpoint_available, endpoint_interrupted) =
                check_endpoint_with_retries(endpoint, socket_type, network_interface, ui.as_ref()).await;
            if endpoint_interrupted {
                return Ok(SubnetIterationOutcome::Interrupted);
            }
            if !endpoint_available {
                handle_endpoint_failure(config, endpoint, network_interface, state_path, state, ui).await?;
                if let Some(ui) = ui.as_ref() {
                    ui.log(
                        EventLevel::Wrn,
                        format!("discarded {subnet_string}: endpoint became unavailable"),
                    );
                }
                return Ok(SubnetIterationOutcome::Continue);
            }

            if let Some(ui) = ui.as_ref() {
                ui.complete_subnet(
                    index + 1,
                    &subnet_string,
                    stats.icmp_alive,
                    stats.tcp_alive,
                    rejected,
                    elapsed_sec,
                );
            } else if scan_progress.is_active() {
                let summary = if stats.tcp_alive > 0 || stats.icmp_alive > 0 {
                    format!(
                        "{} icmp {} tcp {} {:.1}s",
                        subnet_string, stats.icmp_alive, stats.tcp_alive, elapsed_sec
                    )
                } else {
                    format!("{subnet_string} dead {elapsed_sec:.1}s")
                };
                scan_progress.set_message(summary);
            }

            append_result_to_csv(&result, &state.result_csv)?;
            append_result_to_jsonl(&result, &state.result_jsonl)?;
            append_result_to_txt_lists(
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
                ui.subnet_error(index + 1, &subnet_string, &e.to_string());
            } else {
                eprintln!("{}", format!("  error {subnet_string}: {e}").red());
            }
            failed_subnets.insert(subnet_string.clone());
        }
    }

    save_state_snapshot(state_path, state, completed_subnets, failed_subnets)?;

    if stop_every != 0 && state.subnet24_count % stop_every == 0 {
        handle_periodic_stop_action(config, ui.as_ref()).await?;
    }

    Ok(SubnetIterationOutcome::Continue)
}
