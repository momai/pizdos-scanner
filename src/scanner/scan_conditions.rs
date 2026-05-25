use anyhow::Context;
use colored::*;
use std::{
    net::{IpAddr, ToSocketAddrs},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};
use tokio::time::{sleep, Instant};

use crate::icmp::{ping_endpoint, wait_for_any_key};
use crate::init::{
    Config, ConfigEndpointFailureAction, ConfigPingType, ConfigSocketType, ConfigStopAction,
    StopOnAvailableConfig,
};
use crate::scan_state::{save_state, ScanState};
use crate::tui::{EventLevel, ScanUi, ScanUiConfig, WhitelistInfo};

pub(crate) struct StopTargetChecker {
    pub(crate) stop: StopOnAvailableConfig,
    resolved_ip: Option<IpAddr>,
    resolve_error_logged: bool,
}

impl StopTargetChecker {
    pub(crate) fn new(stop: StopOnAvailableConfig) -> Self {
        Self {
            stop,
            resolved_ip: None,
            resolve_error_logged: false,
        }
    }

    pub(crate) fn label(&self) -> String {
        stop_on_available_label(&self.stop)
    }

    fn is_available(
        &mut self,
        network_interface: Option<&str>,
        cancel: Option<&AtomicBool>,
    ) -> (bool, Option<String>) {
        if self.resolved_ip.is_none() {
            match resolve_stop_target_with_timeout(
                &self.stop.target,
                self.stop.port,
                Duration::from_secs(2),
                cancel,
            ) {
                Ok(ip) => self.resolved_ip = Some(ip),
                Err(error) => {
                    if !self.resolve_error_logged {
                        self.resolve_error_logged = true;
                        let msg = format!(
                            "whitelist probe: cannot resolve {} ({error})",
                            self.stop.target
                        );
                        return (false, Some(msg));
                    }
                    return (false, None);
                }
            }
        }

        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return (false, Some("whitelist probe cancelled".to_string()));
        }

        let ip = self.resolved_ip.expect("resolved above");
        let (status, _) = crate::tcp_ping::probe_tcp_with_optional_sni(
            ip,
            self.stop.port,
            None,
            network_interface,
            Duration::from_millis(800),
        );
        (status.is_alive(), None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopProbeResult {
    ContinueUnavailable,
    ContinueAvailable,
    Interrupted,
}

fn resolve_stop_target_with_timeout(
    target: &str,
    port: u16,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
) -> anyhow::Result<IpAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    let lookup = if target.contains(':') {
        target.to_string()
    } else {
        format!("{target}:{port}")
    };

    let target_label = target.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let result = lookup
            .to_socket_addrs()
            .with_context(|| format!("Failed to resolve stop_on_available target {target_label}"))
            .and_then(|addrs| {
                addrs
                    .map(|addr| addr.ip())
                    .next()
                    .context(format!(
                        "No addresses resolved for stop_on_available target {target_label}"
                    ))
            });
        let _ = tx.send(result);
    });

    let started = Instant::now();
    loop {
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            anyhow::bail!("whitelist probe cancelled");
        }
        if started.elapsed() >= timeout {
            anyhow::bail!("DNS timeout for stop_on_available target {target}");
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("DNS resolver thread exited unexpectedly for {target}");
            }
        }
    }
}

fn ping_types_label(ping_type: &[ConfigPingType]) -> Vec<String> {
    ping_type
        .iter()
        .map(|p| match p {
            ConfigPingType::ICMP => "ICMP".to_string(),
            ConfigPingType::TCP => "TCP".to_string(),
        })
        .collect()
}

pub(crate) fn stop_on_available_label(stop: &StopOnAvailableConfig) -> String {
    if stop.target.contains(':') {
        stop.target.clone()
    } else {
        format!("{}:{}", stop.target, stop.port)
    }
}

pub(crate) fn whitelist_info(config: &Config) -> WhitelistInfo {
    match &config.stop_on_available {
        Some(stop) if stop.is_active() => WhitelistInfo {
            label: stop_on_available_label(stop),
            enabled: true,
            check_before: stop.check_before_subnet,
            check_after: stop.check_after_subnet,
        },
        Some(stop) if stop.enabled => WhitelistInfo {
            label: "target пуст".to_string(),
            enabled: false,
            check_before: stop.check_before_subnet,
            check_after: stop.check_after_subnet,
        },
        _ => WhitelistInfo::off(),
    }
}

pub(crate) fn init_scan_ui(
    config: &Config,
    scan_name: &str,
    all_subnets_len: usize,
    completed_count: usize,
    endpoint: &str,
    whitelist_label: Option<&str>,
    tcp_ports: &[u16],
    state: &ScanState,
) -> anyhow::Result<Option<ScanUi>> {
    let mut ui: Option<ScanUi> = if config.use_tui() {
        let socket_type = config
            .socket_type
            .as_ref()
            .context("socket_type is required")?;
        let ui_config = ScanUiConfig {
            scan_name: scan_name.to_string(),
            total_subnets: all_subnets_len,
            resume_count: completed_count,
            endpoint: endpoint.to_string(),
            whitelist: whitelist_info(config),
            tcp_ports: tcp_ports.to_vec(),
            socket_type: format!("{socket_type:?}"),
            ping_types: ping_types_label(&config.ping_type),
            result_jsonl: state.result_jsonl.clone(),
            last_stop: state.stopped_reason.clone(),
        };
        match ScanUi::try_start(ui_config) {
            Ok(ui) => Some(ui),
            Err(e) => {
                eprintln!("TUI unavailable ({e}), falling back to plain output");
                None
            }
        }
    } else {
        None
    };

    if ui.is_none() {
        let mut scan_meta = vec![format!("{scan_name}"), format!("{all_subnets_len} /24")];
        if completed_count > 0 {
            scan_meta.push(format!("resume {completed_count}"));
        }
        if let Some(label) = whitelist_label {
            scan_meta.push(format!("whitelist {label}"));
        } else if !whitelist_info(config).enabled {
            scan_meta.push("whitelist выкл".to_string());
        }
        scan_meta.push(format!("endpoint {endpoint}"));
        println!("{}", scan_meta.join(" · ").cyan());

        if let Some(reason) = &state.stopped_reason {
            println!("{}", format!("last stop: {reason}").dimmed());
        }
    }

    Ok(ui.take())
}

pub(crate) fn probe_stop_target(
    checker: &mut StopTargetChecker,
    ui: Option<&ScanUi>,
    network_interface: Option<&str>,
    log_probe_start: bool,
) -> StopProbeResult {
    if let Some(ui) = ui {
        ui.set_whitelist_status("проверка...");
        if log_probe_start {
            ui.log(EventLevel::Inf, format!("Whitelist probe {}", checker.label()));
        }
    }

    let cancel = ui.map(ScanUi::cancel_flag);
    let (available, warn) = checker.is_available(network_interface, cancel);
    if let Some(warn) = warn {
        if warn.contains("cancelled") {
            return StopProbeResult::Interrupted;
        }
        if let Some(ui) = ui {
            ui.log(EventLevel::Wrn, warn);
        } else {
            eprintln!("{}", warn.yellow());
        }
    }

    if let Some(ui) = ui {
        ui.set_whitelist_status(if available { "доступен" } else { "недоступен" });
    }

    if available {
        StopProbeResult::ContinueAvailable
    } else {
        StopProbeResult::ContinueUnavailable
    }
}

pub(crate) async fn check_endpoint_with_retries(
    endpoint: &str,
    socket_type: &ConfigSocketType,
    network_interface: Option<&str>,
    ui: Option<&ScanUi>,
) -> (bool, bool) {
    let mut endpoint_available = false;
    let max_loop: u32 = 6;
    for cnt in 0..max_loop {
        if ui.is_some_and(ScanUi::cancelled) {
            return (false, true);
        }

        if ping_endpoint(&endpoint.to_string(), 1, socket_type, network_interface) {
            endpoint_available = true;
            break;
        }

        if cnt + 1 < max_loop {
            let delay = if cnt < 4 { 5000 + cnt * 5000 } else { 60000 };
            let retry_msg = format!(
                "Endpoint [{endpoint}] unavailable, retry {}/{} in {}s",
                cnt + 1,
                max_loop,
                delay / 1000
            );
            if let Some(ui) = ui {
                ui.log(EventLevel::Wrn, retry_msg);
                ui.set_endpoint_ok(false);
            } else {
                eprintln!("⚠️ {retry_msg}");
            }
            tokio::time::sleep(Duration::from_millis(delay as u64)).await;
        }
    }

    if let Some(ui) = ui {
        ui.set_endpoint_ok(endpoint_available);
    }
    (endpoint_available, false)
}

pub(crate) async fn handle_endpoint_failure(
    config: &Config,
    endpoint: &str,
    network_interface: Option<&str>,
    state_path: &Path,
    state: &mut ScanState,
    ui: &mut Option<ScanUi>,
) -> anyhow::Result<()> {
    match config.endpoint_failure_action() {
        ConfigEndpointFailureAction::Stop => {
            let msg = format!("Endpoint [{endpoint}] unavailable, stopping");
            if let Some(ui) = ui.take() {
                ui.log(EventLevel::Err, msg.clone());
                save_state(state_path, state)?;
                ui.finish(format!("error: {msg}"));
            } else {
                eprintln!("❌ {msg}");
                save_state(state_path, state)?;
            }
            Err(anyhow::Error::msg("Endpoint unavailable"))
        }
        ConfigEndpointFailureAction::ChangeIp => {
            let task = config
                .task
                .as_ref()
                .context("task config is required for endpoint_failure_action = ChangeIp")?;
            let change_ip_url = task
                .change_ip_url
                .as_ref()
                .context("task.change_ip_url is required for endpoint_failure_action = ChangeIp")?;
            let rotate_msg = format!("Endpoint [{endpoint}] unavailable, requesting IP rotation");
            if let Some(ui) = ui.as_ref() {
                ui.log(EventLevel::Wrn, rotate_msg);
            } else {
                eprintln!("⚠️ {rotate_msg}");
            }
            crate::utils::change_ip(change_ip_url).await?;
            let delay_seconds = task.delay_seconds.unwrap_or(5);
            sleep(Duration::from_secs(delay_seconds)).await;

            if !ping_endpoint(
                &endpoint.to_string(),
                1,
                config.socket_type.as_ref().unwrap(),
                network_interface,
            ) {
                let msg = format!(
                    "Endpoint [{endpoint}] still unavailable after IP rotation, stopping"
                );
                if let Some(ui) = ui.take() {
                    ui.log(EventLevel::Err, msg.clone());
                    save_state(state_path, state)?;
                    ui.finish(format!("error: {msg}"));
                } else {
                    eprintln!("❌ {msg}");
                    save_state(state_path, state)?;
                }
                return Err(anyhow::Error::msg(
                    "Endpoint unavailable after IP rotation",
                ));
            }
            Ok(())
        }
    }
}

pub(crate) async fn handle_periodic_stop_action(
    config: &Config,
    ui: Option<&ScanUi>,
) -> anyhow::Result<()> {
    let Some(task) = &config.task else {
        return Ok(());
    };
    match &task.stop_action {
        ConfigStopAction::Delay => {
            let delay_seconds = task.delay_seconds.unwrap();
            let msg = format!("PAUSED...delay {delay_seconds} sec");
            if let Some(ui) = ui {
                ui.log(EventLevel::Inf, msg);
            } else {
                println!("{msg}");
            }
            sleep(Duration::from_secs(delay_seconds)).await;
        }
        ConfigStopAction::ChangeIp => {
            let change_ip_url = task.change_ip_url.as_ref().unwrap();
            if let Some(ui) = ui {
                ui.log(EventLevel::Inf, "PAUSED...change IP");
            }
            crate::utils::change_ip(change_ip_url).await?;
        }
        ConfigStopAction::Prompt => {
            if let Some(ui) = ui {
                ui.log(
                    EventLevel::Wrn,
                    "Prompt pause: switch console to plain mode for wait_for_any_key",
                );
            }
            wait_for_any_key()?;
        }
    }
    Ok(())
}

pub(crate) fn graceful_stop_on_available(
    state_path: &Path,
    state: &mut ScanState,
    stop: &StopOnAvailableConfig,
    subnet: Option<&str>,
    ui: Option<&ScanUi>,
) -> anyhow::Result<()> {
    let label = stop_on_available_label(stop);
    state.stopped_reason = Some(format!("stop_on_available:{label}"));
    state.finished = false;
    save_state(state_path, state)?;

    let msg = match subnet {
        Some(subnet) => format!("whitelist stop: {label} available, discarded {subnet}"),
        None => format!("whitelist stop: {label} available"),
    };

    if let Some(ui) = ui {
        ui.log(EventLevel::Wrn, msg);
        ui.set_whitelist_status("доступен — стоп");
    } else {
        println!("{}", msg.bright_yellow());
    }

    Ok(())
}
