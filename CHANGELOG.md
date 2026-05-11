# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-05-11

### Added

- Initial crate skeleton.
- `FuzzFindingKind` enum: `Crash`, `Timeout`, `OutOfMemory`.
- `FuzzBudget` enum: `Time(Duration)`, `Executions(u64)`.
- `FuzzRun` builder with `new`, `budget`, `fuzz_budget`, `execute`.
- `FuzzFinding` struct: kind, reproducer_path, summary.
- `FuzzResult` with `into_report` producing severity-mapped checks.
- `FuzzError` for tool-missing / nightly-missing / subprocess / target-not-found.
- Reproducer paths attached as `Evidence::FileRef` for replay.
- Smoke tests covering budgets, empty results, crash classification.

### Note

This is the name-claim release. The actual `cargo-fuzz` subprocess
integration lands in `0.9.1`.

[Unreleased]: https://github.com/jamesgober/dev-fuzz/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/jamesgober/dev-fuzz/releases/tag/v0.9.0
