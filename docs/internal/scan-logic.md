# Scan Logic (Internal Notes)

## Runtime Entry Points
- CLI routing is in `src/main.rs` (arguments + dispatch only).
- Command handlers are in `src/commands/*`:
  - `scan.rs` (`subnets`, `subnet`, `geoip-list`, `geoip-scan`, `--update`),
  - `icmp_fast.rs` (`icmp-fast`),
  - `tcp_scan_file.rs` (`tcp-scan-file`),
  - `net.rs` (`myip`, `info`, `test`),
  - `finalize.rs` (`finalize`).
- Full subnet orchestration entry remains `scan_networks()` in `src/scanner.rs`.

## High-Level Scan Pipeline
1. Initialize GeoIP service (graceful fallback to `N/A` geo fields).
2. Run ICMP preflight if ICMP is enabled (with actionable Linux hint for `ping_group_range`).
3. Normalize CIDR input and expand into unique `/24` blocks (`expand_to_24()`).
4. Load or create resume state (`results/state/<job_id>.json`).
5. Start UI (TUI or plain progress).
6. Run subnet execution loop:
   - sequential path (`scan_loop::process_subnet_iteration`), or
   - parallel path (`parallel::run_parallel_subnets`) when `subnet_parallelism > 1`.
7. Persist partial results and state snapshots incrementally.
8. Finalize state and optional aggregate output files.

## Module Boundaries

### `src/scanner.rs`
- Top-level coordinator and shared setup:
  - source normalization (`scan_source`, `fallback_country_for_source`),
  - CIDR cleanup/expansion (`expand_to_24`, comment-safe),
  - state bootstrap/resume and finalization,
  - selecting sequential vs parallel runtime,
  - creating global host-probe semaphore (`host_probe_parallelism`).

### `src/scanner/scan_conditions.rs`
- Cross-cutting controls:
  - whitelist (`stop_on_available`) checks and stop flow,
  - endpoint retry loop and failure handling,
  - periodic task actions (`Delay` / `ChangeIp` / `Prompt`),
  - UI bootstrap.

### `src/scanner/scan_loop.rs`
- Sequential `/24` worker logic:
  - pre/post whitelist checks,
  - one subnet probe (`icmp::process_subnet`),
  - endpoint gate before committing results,
  - append output + save state snapshot.

### `src/scanner/parallel.rs`
- Parallel `/24` scheduler and commit policy:
  - bounded number of active subnet workers (`subnet_parallelism`),
  - shared global host-probe limit via semaphore (`host_probe_parallelism`),
  - pending batch buffering + endpoint gate before commit,
  - stop-on-available and cancellation integration across active workers.

### `src/icmp.rs`
- Probe primitives only:
  - `probe_host()` (ICMP/TCP attempts with `ProbeTuning`),
  - `process_subnet()` (scan one `/24`, aggregate stats),
  - no high-level scan orchestration.

### `src/scan_state.rs`
- Resume/persistence model:
  - `ScanState`,
  - state path/job id helpers,
  - load/save/snapshot,
  - plain-mode progress helper (`ScanProgress`).

## Per-Subnet Probe Model
- `process_subnet()` scans `.1..=.254`.
- Every host probe respects `ProbeTuning` (`attempts`, `icmp_timeout`, retry delay, `tcp_timeout`).
- Aggregates `SubnetProbeStats`:
  - `icmp_alive`, `tcp_alive`,
  - per-port alive/rejected counters,
  - host-level probe records.

## Parallelism Model (Current)
- `subnet_parallelism`: how many `/24` workers run concurrently.
- `host_probe_parallelism`: global cap for all in-flight host probes across all workers.
- Effective load is controlled at one level (shared semaphore), so adding `/24` workers does not multiply probe fan-out quadratically.

## Stop / Endpoint / Cancellation Semantics
- Whitelist checks (`stop_on_available`) run before and after subnet work.
- Endpoint checks run with retries; failures can stop or trigger `change_ip`.
- In parallel mode, results can be temporarily buffered and discarded if endpoint becomes unavailable before commit.
- Cancellation is cooperative (`ScanUi::cancelled()` + atomic flag checks); interrupt keeps resumable state.

## Persistence & Outputs
- Incremental append per committed subnet:
  - CSV (`append_result_to_csv`),
  - JSONL (`append_result_to_jsonl`),
  - `*_alive.txt` / `*_rejected.txt` (`append_result_to_txt_lists`).
- On normal completion:
  - `state.finished = true`,
  - `state.stopped_reason = None`.
- If `logger_filetype` requests, final aggregate CSV/JSON is generated at the end.
