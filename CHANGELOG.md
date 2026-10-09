# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.2] - 2026-10-09

Finding-detection fixes from a review pass, a hard run time limit, and
the MSRV rollback to Rust 1.75. The rollback follows `dev-fixtures`
0.9.5 swapping `tempfile` for `mod-tempdir` 1.0, which removed the
`getrandom 0.4.2 -> edition2024` chain that held the dev-* collection
at 1.85.

### Added

- `FuzzRun::run_timeout(Duration)`, a hard wall-clock limit on the
  whole run. The time budget does not cover the build or one slow input
  (libFuzzer's default per-input timeout is 1200 s). On expiry the
  process tree is killed and findings already written are kept.
- `VERSION` constant with the crate version as compiled, so tools that
  bundle this crate can report what is actually linked.

### Fixed

- Sanitizer reports (`SUMMARY: AddressSanitizer: ...`, LeakSanitizer
  and the rest) were not recognized. An ASan crash came back as
  `SubprocessFailed` with no reproducer; it is now a Crash finding, and
  `leak-*` artifacts are handled.
- Reproducers were searched only 10 lines forward and 20 lines back, so
  a timeout artifact printed before a deep stack trace came out as
  "unknown reproducer". The search now covers everything between
  neighbouring `SUMMARY` lines and prefers an artifact whose prefix
  matches the finding kind. An artifact with no `SUMMARY` line
  (truncated output) still becomes a finding.
- Rust panics were summarized as "deadly signal"; the panic message is
  used now.
- Indented stack frames (`#35 0x...`) were counted as executions.
  Status lines must start in column 0, and `Done N runs` and
  `stat::number_of_executed_units` are read too.
- A crash on an allow-listed input made `execute()` return
  `SubprocessFailed`, so the allow-list was useless for crashes.
- Nightly detection accepted any toolchain whose name starts with
  `nightly`, including dated ones that `cargo +nightly` cannot use. It
  now probes `cargo +nightly --version` with `RUSTUP_AUTO_INSTALL=0`, so
  nothing is downloaded. Tool detection only treats cargo's "no such
  command" error as not installed, and a missing work dir gives a clear
  error.
- The unknown-reproducer placeholder was attached as a file reference,
  which ended up in SARIF output. Execution counts above `i64::MAX` went
  negative in evidence. Allow-list matching now handles `\` paths on
  any host.

### Changed

- Subprocess error details carry the last 60 lines of stderr instead of
  the whole log.
- `rust-version` lowered from `1.85` to `1.75`. CI's MSRV job now
  builds on 1.75 against an MSRV-compatible lockfile; it was still
  pinned to 1.85.

### Documentation

- New README sections on what gets detected, budgets versus hangs, how
  a missing tool or nightly is detected, and the reproducer
  placeholder. MSRV section says 1.75.
- `docs/API.md`: builder table and error conditions.

[0.9.2]: https://github.com/jamesgober/dev-fuzz/releases/tag/v0.9.2

## [0.9.1] - 2026-05-12

Documentation and SEO pass. No code changes.

### Changed

- README header standardized: Rust logo image, MSRV badge between CI and docs.rs (was at the end, lowercase label), copyright block at bottom.
- Subtitle now reads `FUZZ TESTING WORKFLOW FOR RUST` (was `FUZZING HARNESS INTEGRATION FOR RUST`). Plainer language; matches what users search for.
- Tagline rewritten to lead with what's wrapped (`cargo-fuzz`) and what's captured (crashes / timeouts / OOMs with reproducer paths).
- `## The dev-* suite` retitled to `The dev-* collection` and expanded with the full 14-crate map.
- `Cargo.toml` description rewritten: leads with budgeted runs, finding types, reproducer paths, sanitizer choice.
- `Cargo.toml` keywords retuned: dropped `verification` and `ai-tools`, added `cargo-fuzz` and `testing` for crates.io search.

### Added

- "Part of the `dev-*` verification collection" block on the README, under the intro, linking the umbrella `dev-tools` crate.

[0.9.1]: https://github.com/jamesgober/dev-fuzz/releases/tag/v0.9.1

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
