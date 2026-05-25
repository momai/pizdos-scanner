# Scan Logic (Internal Notes)

## Main Entry
- Public entrypoint for orchestration is `scan_networks()` in `src/scanner.rs`.
- `src/icmp.rs` now contains probing primitives (ICMP/TCP probing and subnet processing), not full scan orchestration.
- High-level pipeline:
  1. Initialize GeoIP services (with graceful fallback).
  2. Validate ICMP capability when ICMP mode is enabled.
  3. Expand input CIDRs to unique `/24` blocks (`expand_to_24()`).
  4. Build/load resume state (`results/state/<job_id>.json`).
  5. Initialize UI (plain progress bar or TUI).
  6. Iterate `/24` blocks through loop runtime.
  7. Persist state/results incrementally and finalize outputs.

## Module Boundaries

### `src/scanner.rs`
- Top-level coordinator:
  - input normalization (`scan_source`, `fallback_country_for_source`, `expand_to_24`),
  - state bootstrap/resume,
  - per-subnet loop control,
  - final completion/interruption handling.

### `src/scanner/scan_conditions.rs`
- Cross-cutting scan conditions:
  - whitelist/`stop_on_available` logic (`StopTargetChecker`, `probe_stop_target`),
  - endpoint health retry/failure actions,
  - periodic task stop actions (`Delay`/`ChangeIp`/`Prompt`),
  - UI bootstrap (`init_scan_ui`).

### `src/scanner/scan_loop.rs`
- Single `/24` runtime unit:
  - `process_subnet_iteration(SubnetIterationCtx)`,
  - pre/post whitelist checks,
  - run `process_subnet()` from `icmp`,
  - append outputs, save snapshot, endpoint gate, stop-every action.

### `src/scan_state.rs`
- Resume and persistence model:
  - `ScanState`,
  - job ID derivation and state path,
  - load/save/snapshot helpers,
  - plain-mode progress bar (`ScanProgress`).

## Per-Subnet Pipeline
- `process_subnet()` in `src/icmp.rs` scans one `/24`:
  - enumerate `.1..=.254`,
  - probe each host (`probe_host()`),
  - aggregate `SubnetProbeStats`:
    - `icmp_alive`,
    - `tcp_alive`,
    - per-port `tcp_port_alive`,
    - per-port `tcp_port_rejected`,
    - host-level records.

## Stop-on-Available (Whitelist)
- Managed by `StopTargetChecker` in `scan_conditions`.
- DNS resolution is bounded and cancel-aware:
  - dedicated resolver thread,
  - 2s timeout,
  - cancellation checks while waiting.
- Probe points:
  - before subnet scan (`check_before_subnet`),
  - after subnet scan (`check_after_subnet`).
- If stop is triggered after subnet processing, the current subnet result is intentionally dropped (preserves previous behavior).

## Endpoint Health Gate
- After each subnet, endpoint health is checked with retries (`check_endpoint_with_retries`).
- Failure actions:
  - `Stop`: save state and terminate,
  - `ChangeIp`: call `task.change_ip_url`, wait delay, re-check endpoint.

## Cancellation Model
- Cancellation is cooperative via `ScanUi::cancelled()` / atomic flag checks.
- Checked in critical points:
  - before subnet iteration,
  - during whitelist checks,
  - during endpoint retry loop.
- On interrupt:
  - state snapshot is preserved,
  - run exits cleanly,
  - next run can resume.

## Persistence/Outputs
- Incremental per-subnet append:
  - CSV (`append_result_to_csv`),
  - JSONL (`append_result_to_jsonl`),
  - `*_alive.txt` / `*_rejected.txt` (`append_result_to_txt_lists`).
- State is updated every subnet; on normal completion:
  - `state.finished = true`,
  - `state.stopped_reason = None`.
- Optional final aggregate files are produced when `logger_filetype` includes CSV/JSON.

## Refactor Status (May 2026)
- `scan_networks` orchestration moved out of `icmp` into `scanner`.
- Scanner split into dedicated submodules (`scan_conditions`, `scan_loop`).
- Functional behavior preserved; responsibilities are now explicit and easier to evolve/test.
