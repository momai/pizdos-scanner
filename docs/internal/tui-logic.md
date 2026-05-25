# TUI Logic (Internal Notes)

## Purpose
- `src/tui.rs` provides an optional interactive dashboard.
- Scanner must stay functional without TUI (`plain` mode is first-class).

## Startup Lifecycle
- `ScanUi::try_start()`:
  1. creates shared dashboard state (`Arc<Mutex<ScanDashboard>>`),
  2. configures Ctrl+C handler (sets cancel flag),
  3. spawns draw thread (`run_loop()`),
  4. waits for initial draw readiness (timeout guarded).
- If startup fails, caller falls back to plain console output.

## Draw Loop
- `run_loop()` owns terminal setup/teardown:
  - enter raw mode,
  - alternate screen,
  - periodic render (~80ms),
  - key handling (`Ctrl+C`),
  - graceful restore via RAII guard.
- Dashboard sections:
  - header stats + subnet progress bar,
  - recent `/24` table,
  - events log,
  - control panel (endpoint/whitelist/session stats, workers usage).

## Data Model
- `ScanDashboard` stores rolling state:
  - progress counters,
  - inflight subnet list (not only one "current"),
  - configured/active worker counters,
  - recent rows,
  - events ring buffer,
  - whitelist/endpoint status.
- Scanner updates state through narrow methods:
  - `set_scanning()`
  - `set_inflight_subnets()`
  - `complete_subnet()`
  - `subnet_error()`
  - `set_whitelist_status()`
  - `set_endpoint_ok()`

## ETA Model
- ETA is based on completed subnet timings only:
  - uses accumulated duration of finished subnets,
  - computes average seconds per subnet from completed history,
  - projects remaining time from remaining `/24` count.
- This avoids large ETA jumps caused by partially running subnets.

## Cancellation
- Cancellation is cooperative (`AtomicBool`):
  - set by Ctrl+C handler,
  - observed by scan loop and stop-on-available probe,
  - observed by parallel scheduler as well.
- Expected behavior:
  - sequential mode: exit between safe checkpoints,
  - parallel mode: scheduler aborts active tasks and exits with resumable state snapshot.

## Console Modes
- Controlled by `Config::use_tui()` (`src/init.rs`):
  - `plain`: always plain
  - `tui`: force TUI
  - `auto`: TUI only when terminal is interactive **and** `PIZDOS_TUI` enables it.

## Parallel Runtime Visibility
- In parallel subnet mode, TUI shows:
  - multiple inflight `/24` rows,
  - `Workers X/Y` (`X` active, `Y` configured subnet parallelism),
  - endpoint/whitelist events that affect commit/discard decisions.

## Operational Caveats
- Docker/CI commonly lacks interactive TTY -> prefer `plain`.
- If terminal state is corrupted after abnormal stop, use `reset`.
