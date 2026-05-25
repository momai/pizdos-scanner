use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::init::Config;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub(crate) struct SessionSummary {
    pub scanned_this_run: usize,
    pub elapsed_seconds: f64,
    pub workers: usize,
    pub rate_total_per_min: f64,
    pub rate_per_worker_per_min: f64,
    pub avg_seconds_per_subnet: f64,
    pub finished_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ScanState {
    pub version: u8,
    pub job_id: String,
    pub scan_name: String,
    pub result_csv: String,
    pub result_jsonl: String,
    #[serde(default)]
    pub result_alive_txt: String,
    #[serde(default)]
    pub result_rejected_txt: String,
    pub completed_subnets: Vec<String>,
    pub failed_subnets: Vec<String>,
    pub subnet24_count: u32,
    pub created_at: String,
    pub updated_at: String,
    pub finished: bool,
    #[serde(default)]
    pub stopped_reason: Option<String>,
    #[serde(default)]
    pub last_session: Option<SessionSummary>,
}

fn timestamp() -> String {
    chrono::Local::now().format("%Y%m%d_%H%M%S").to_string()
}

fn operator_part(config: &Config) -> String {
    config
        .operator
        .as_deref()
        .filter(|operator| !operator.is_empty())
        .map(|operator| format!("_{operator}_"))
        .unwrap_or_else(|| "_".to_string())
}

fn update_hash(hash: &mut u64, value: &str) {
    for byte in value.as_bytes() {
        *hash ^= *byte as u64;
        *hash = hash.wrapping_mul(0x100000001b3);
    }
}

pub(crate) fn build_job_id(config: &Config, scan_name: &str, networks: &[String]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    update_hash(&mut hash, "result_schema_tcp_txt_lists_v1");
    update_hash(&mut hash, scan_name);
    update_hash(&mut hash, &format!("{:?}", config.ping_type));
    update_hash(&mut hash, &format!("{:?}", config.tcp_ports()));
    update_hash(&mut hash, config.tcp_sni_host.as_deref().unwrap_or(""));
    update_hash(&mut hash, config.operator.as_deref().unwrap_or(""));
    for network in networks {
        update_hash(&mut hash, network);
    }
    format!("{hash:016x}")
}

pub(crate) fn state_path(config: &Config, job_id: &str) -> PathBuf {
    Path::new(config.resume_state_dir()).join(format!("{job_id}.json"))
}

pub(crate) fn load_state(path: &Path) -> anyhow::Result<Option<ScanState>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(path)?;
    let state = serde_json::from_str(&content)?;
    Ok(Some(state))
}

pub(crate) fn save_state(path: &Path, state: &mut ScanState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    state.updated_at = chrono::Local::now().to_rfc3339();
    fs::write(path, serde_json::to_string_pretty(state)?)?;
    Ok(())
}

pub(crate) fn create_state(config: &Config, scan_name: &str, job_id: String) -> ScanState {
    let result_path = PathBuf::from(config.results_dir());
    let date_string = timestamp();
    let filename = format!("{scan_name}{}{date_string}", operator_part(config));
    let result_csv = result_path
        .join(format!("{filename}.csv"))
        .to_string_lossy()
        .to_string();
    let result_jsonl = result_path
        .join(format!("{filename}.jsonl"))
        .to_string_lossy()
        .to_string();
    let result_alive_txt = result_path
        .join(format!("{filename}_alive.txt"))
        .to_string_lossy()
        .to_string();
    let result_rejected_txt = result_path
        .join(format!("{filename}_rejected.txt"))
        .to_string_lossy()
        .to_string();
    let now = chrono::Local::now().to_rfc3339();

    ScanState {
        version: 1,
        job_id,
        scan_name: scan_name.to_string(),
        result_csv,
        result_jsonl,
        result_alive_txt,
        result_rejected_txt,
        completed_subnets: Vec::new(),
        failed_subnets: Vec::new(),
        subnet24_count: 1,
        created_at: now.clone(),
        updated_at: now,
        finished: false,
        stopped_reason: None,
        last_session: None,
    }
}

pub(crate) fn save_state_snapshot(
    state_path: &Path,
    state: &mut ScanState,
    completed_subnets: &HashSet<String>,
    failed_subnets: &HashSet<String>,
) -> anyhow::Result<()> {
    state.completed_subnets = completed_subnets.iter().cloned().collect();
    state.failed_subnets = failed_subnets.iter().cloned().collect();
    state.subnet24_count += 1;
    save_state(state_path, state)
}

pub(crate) struct ScanProgress(Option<ProgressBar>);

impl ScanProgress {
    pub fn new(enabled: bool, total: usize, resume_done: usize) -> Self {
        if !enabled || total == 0 {
            return Self(None);
        }
        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::with_template(
                " [{bar:50.cyan/blue}] {pos}/{len} ({percent_precise}%) eta {eta} {msg}",
            )
            .unwrap()
            .progress_chars("█▓░"),
        );
        pb.set_position(resume_done as u64);
        Self(Some(pb))
    }

    pub fn is_active(&self) -> bool {
        self.0.is_some()
    }

    pub fn set_position(&self, done: usize, subnet: &str) {
        if let Some(pb) = &self.0 {
            pb.set_position(done as u64);
            pb.set_message(subnet.to_string());
        }
    }

    pub fn set_message(&self, message: impl Into<String>) {
        if let Some(pb) = &self.0 {
            pb.set_message(message.into());
        }
    }

    pub fn complete_subnet(&self) {
        if let Some(pb) = &self.0 {
            pb.inc(1);
        }
    }
}

impl Drop for ScanProgress {
    fn drop(&mut self) {
        if let Some(pb) = self.0.take() {
            pb.finish_and_clear();
        }
    }
}
