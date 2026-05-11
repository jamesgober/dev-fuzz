# dev-fuzz — Project Specification (REPS)

> Rust Engineering Project Specification.
> Normative language follows RFC 2119.

## 1. Purpose

`dev-fuzz` MUST run fuzz targets and emit findings as
`dev-report::Report`. Each finding MUST carry a reproducer path so the
crash can be replayed.

## 2. Scope

This crate MUST provide:

- `FuzzFindingKind` enum (`Crash`, `Timeout`, `OutOfMemory`).
- `FuzzBudget` enum (`Time`, `Executions`).
- `FuzzRun` builder.
- `FuzzFinding` and `FuzzResult` types.
- `FuzzError` covering tool-missing, nightly-missing, subprocess
  failure, and target-not-found.

This crate SHOULD provide (later versions):

- `cargo-fuzz` subprocess integration (`0.9.1`).
- Coverage-guided corpus management.
- Multiple-target orchestration in one run.
- Sanitizer selection (ASAN, UBSAN, MSAN).

This crate MUST NOT:

- Implement a fuzzer. We wrap libFuzzer via `cargo-fuzz`.
- Replace AFL or honggfuzz. Pick one engine; the choice is libFuzzer.

## 3. Severity policy

| Finding kind     | dev-report::Severity |
|------------------|----------------------|
| `Crash`          | `Critical`           |
| `OutOfMemory`    | `Error`              |
| `Timeout`        | `Warning`            |

## 4. Reproducer requirement

Every `FuzzFinding` MUST carry a reproducer_path pointing at the
input that triggered the finding. The path MUST be attached to the
emitted `CheckResult` as `Evidence::FileRef`.

## 5. Determinism

Fuzzing is inherently non-deterministic. We don't claim deterministic
results across runs. However, the report-shape and severity mapping
MUST be deterministic given a set of findings.

## 6. Stability

Through `0.9.x` the public API MAY shift. The `1.0` release pins the
API and the severity policy.
