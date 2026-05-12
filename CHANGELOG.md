# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-05-12

Foundation release. Replaces the `0.1.0` name-claim with full
`cargo-fuzz` (libFuzzer) integration.

### Added

- Real `cargo +nightly fuzz run <target>` subprocess integration. Detects missing `cargo-fuzz` and missing nightly toolchain as typed `FuzzError::ToolNotInstalled` / `FuzzError::NightlyRequired`; runs `cargo fuzz list` ahead of time to detect missing targets as `FuzzError::TargetNotFound`.
- libFuzzer stderr parser at `src/runner.rs` — recognizes `SUMMARY: libFuzzer:` deadly-signal / timeout / out-of-memory headers, captures the preceding panic / ERROR line as the summary, scans nearby lines for the `Test unit written to <path>` reproducer path, and falls back to a clear sentinel when the path is missing.
- Execution count derived from libFuzzer's periodic `#N` status lines (the highest seen is recorded).
- Severity mapping per REPS § 3: `Crash` → `Critical`; `OutOfMemory` → `Error`; `Timeout` → `Warning`. Now exposed as `FuzzFindingKind::severity()` and used by `into_report` automatically.
- `FuzzFindingKind::label()` returns a stable lowercase short label (`crash`, `timeout`, `oom`) used in `CheckResult` names and as `Evidence` tags.
- `FuzzRun` builder gains the full surface: `in_dir(path)`, `sanitizer(Sanitizer)`, `timeout_per_iter(Duration)`, `rss_limit_mb(u32)`, `allow(name)`, `allow_all(iter)`, `target_name()`, `subject_version()`.
- New `Sanitizer` enum (`Address`, `Leak`, `Memory`, `Thread`, `None`) wired into `cargo fuzz run --sanitizer <kind>`.
- Allow-list filters findings by reproducer-file basename so triaged false positives (e.g. `crash-deadbeef`) stay out of the report.
- `FuzzResult::total_findings`, `count_of(kind)`, `worst_severity()` helpers.
- `FuzzResult::into_report` emits one `CheckResult` per finding named `fuzz::<target>::<kind>` tagged `fuzz` plus the kind label (`crash` / `timeout` / `oom`). The reproducer path rides along as `Evidence::FileRef`. No findings → one passing check carrying numeric `executions` evidence.
- New `producer` module exposing `FuzzProducer`: a `dev_report::Producer` adapter. Subprocess failures map to a single `CheckResult::fail("fuzz::<target>", Severity::Critical)` tagged `fuzz` + `subprocess`.
- 26 unit tests across `lib.rs`, `runner.rs`, `producer.rs`. Coverage includes: severity / label mapping, budget → libFuzzer flag conversion, sanitizer flags, builder chain, JSON round-trip on `FuzzResult`, libFuzzer stderr parsing for crash / timeout / OOM (each variant), reproducer-path extraction (before *and* after the `SUMMARY` line), unknown libFuzzer summary falling back to `Crash`, missing reproducer falling back to a sentinel, allow-list filtering by basename, execution-count picking the max status line.
- 6 integration tests in `tests/smoke.rs` (unchanged from 0.1.0; still compile and pass against the expanded API).
- Examples: `basic.rs` (graceful tool-missing handling), `executions_budget.rs`, `with_limits.rs` (sanitizer + timeout + RSS + allow-list), `producer.rs` (gated by `DEV_FUZZ_EXAMPLE_RUN`).

### Changed

- `cargo install cargo-fuzz` and `rustup toolchain install nightly` are now real runtime requirements (previously declared but not invoked).
- README rewritten: removes the "subprocess integration lands in 0.9.1" placeholder, documents `Sanitizer`, `timeout_per_iter`, `rss_limit_mb`, the allow-list workflow, and the producer integration. MSRV pinned at 1.85.
- REPS.md tightened: the "SHOULD provide" items (subprocess integration, sanitizer selection) become MUST-have for 0.9.x.
- CI workflow: new `integration` job installs `cargo-fuzz` via `taiki-e/install-action@v2` and the nightly toolchain via `dtolnay/rust-toolchain@nightly`. Path-dep `../dev-report` is cloned in every job; `actions/checkout@v5` everywhere.

### Dependencies

- Added: `serde` 1.0 (derive feature), `serde_json` 1.0. Required for serializing `FuzzResult` / `FuzzFinding` and for future round-trip / wire-format consumers.
- Added: `tempfile` 3 as a `dev-dependency`.

### Note

`0.1.0` was a name-claim publish with a stub `execute()` returning an empty result. The public API additions are mostly additive — existing methods (`new`, `budget`, `fuzz_budget`, `execute`) keep their signatures. `FuzzRun` gained private fields, so callers using the builder pattern continue to compile unchanged.

[Unreleased]: https://github.com/jamesgober/dev-fuzz/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/jamesgober/dev-fuzz/releases/tag/v0.9.0
[0.1.0]: https://github.com/jamesgober/dev-fuzz/releases/tag/v0.1.0
