# dev-fuzz — Project Specification (REPS)

> Rust Engineering Project Specification.
> Normative language follows RFC 2119.

## 1. Purpose

`dev-fuzz` MUST run libFuzzer-based fuzz targets and emit findings as
`dev-report::Report`. Each finding MUST carry a reproducer path so the
crash can be replayed.

## 2. Scope

This crate MUST provide:

- `FuzzFindingKind` enum (`Crash`, `Timeout`, `OutOfMemory`).
- `FuzzBudget` enum (`Time`, `Executions`).
- `Sanitizer` enum (`Address`, `Leak`, `Memory`, `Thread`, `None`).
- `FuzzRun` builder with `new`, `budget`, `in_dir`, `sanitizer`,
  `timeout_per_iter`, `rss_limit_mb`, `allow`, `allow_all`,
  `target_name`, `subject_version`, `execute` methods.
- `FuzzFinding` and `FuzzResult` types with severity helpers
  (`severity`, `label`, `count_of`, `worst_severity`,
  `total_findings`).
- `FuzzError` covering tool-missing, nightly-missing, subprocess
  failure, and target-not-found.
- A `FuzzProducer` adapter implementing `dev_report::Producer`,
  mapping subprocess failures to a failing `CheckResult` rather than
  panicking.
- `cargo-fuzz` subprocess integration.
- libFuzzer stderr parsing for crash / timeout / OOM events with
  reproducer-path extraction.

This crate MAY provide later:

- Coverage-guided corpus management.
- Multiple-target orchestration in one run.
- Custom dictionary / seed corpus configuration.

This crate MUST NOT:

- Implement a fuzzer. We wrap libFuzzer via `cargo-fuzz`.
- Replace AFL or honggfuzz. Pick one engine; the choice is libFuzzer.

## 3. Severity policy

| Finding kind     | dev-report::Severity |
|------------------|----------------------|
| `Crash`          | `Critical`           |
| `OutOfMemory`    | `Error`              |
| `Timeout`        | `Warning`            |

`FuzzFindingKind::severity()` MUST return the mapping above. The
`into_report` flow MUST use this method rather than open-coding the
mapping again.

## 4. Reproducer requirement

Every `FuzzFinding` MUST carry a `reproducer_path` pointing at the
input that triggered the finding. The path MUST be attached to the
emitted `CheckResult` as `Evidence::FileRef` with the label
`"reproducer"`.

When the libFuzzer output does not include a reproducer path, the
runner MUST emit a sentinel string of the form
`<unknown reproducer for <kind>>` so consumers can detect the missing
artifact rather than seeing an empty path.

## 5. Determinism

Fuzzing is inherently non-deterministic across runs. The crate
specifically does NOT claim deterministic findings.

However, the report-shape and severity mapping MUST be deterministic
given a set of findings: `FuzzResult::into_report` MUST produce the
same `Report` (modulo the auto-stamped timestamps) for equal input,
and `FuzzFindingKind::severity()` MUST be a pure mapping.

## 6. Tool dependencies

`cargo-fuzz` MUST be installed externally. It also requires the
nightly Rust toolchain (`rustup toolchain install nightly`). The
crate invokes it via `cargo +nightly fuzz run <target>`. Detection of
missing prerequisites produces `FuzzError::ToolNotInstalled` /
`FuzzError::NightlyRequired`.

Subprocess failures with no recoverable output MUST surface as
`FuzzError::SubprocessFailed(stderr)`. Missing targets MUST surface
as `FuzzError::TargetNotFound(name)`. Neither MUST cause a panic.

`cargo-fuzz` returns non-zero exit when libFuzzer finds an issue —
this is the success path for `dev-fuzz`. The crate MUST parse stderr
regardless of exit code and only surface a hard error when both the
stderr parse yielded no findings *and* the exit code is non-zero.

## 7. Producer contract

`FuzzProducer::produce()` MUST always return a `Report`. It MUST NOT
panic on subprocess failure; instead, it MUST emit a single
`CheckResult::fail("fuzz::<target>", Severity::Critical)` carrying
the error message in `detail` and the tags `fuzz` + `subprocess`.

## 8. Stability

Through `0.9.x` the public API MAY shift. The `1.0` release pins the
API and the severity policy table above. The wire format of
`FuzzResult`, `FuzzFinding`, and the JSON shape emitted through
`dev-report` MUST stay stable from `1.0` onward.
