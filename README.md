<h1 align="center">
    <strong>dev-fuzz</strong>
    <br>
    <sup><sub>FUZZING HARNESS INTEGRATION FOR RUST</sub></sup>
</h1>

<p align="center">
    <a href="https://crates.io/crates/dev-fuzz"><img alt="crates.io" src="https://img.shields.io/crates/v/dev-fuzz.svg"></a>
    <a href="https://crates.io/crates/dev-fuzz"><img alt="downloads" src="https://img.shields.io/crates/d/dev-fuzz.svg"></a>
    <a href="https://docs.rs/dev-fuzz"><img alt="docs.rs" src="https://docs.rs/dev-fuzz/badge.svg"></a>
    <a href="https://github.com/jamesgober/dev-fuzz/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/dev-fuzz/actions/workflows/ci.yml/badge.svg"></a>
    <img alt="MSRV" src="https://img.shields.io/badge/msrv-1.85%2B-blue.svg?style=flat-square" title="Rust Version">
</p>

<p align="center">
    Captures crashes, timeouts, and OOM events with reproducer inputs.<br>
    Part of the <code>dev-*</code> verification suite.
</p>

---

## What it does

`dev-fuzz` wraps [`cargo-fuzz`](https://crates.io/crates/cargo-fuzz)
(libFuzzer-based) and emits findings as a
[`dev-report::Report`](https://docs.rs/dev-report). Each finding
carries the reproducer path that triggered it as
`Evidence::FileRef`, so the input can be replayed and debugged.

## What is fuzzing?

Fuzzing feeds random or guided-random inputs to your code looking for
crashes, panics, or unexpected behavior. It's the standard tool for:

- Parsers
- Deserializers
- Network protocol handlers
- Anything that takes untrusted bytes

A typical fuzz session runs for minutes to hours and feeds billions of
inputs through the target.

## Quick start

```toml
[dependencies]
dev-fuzz = "0.9"
```

One-time tool install:

```bash
cargo install cargo-fuzz
rustup toolchain install nightly      # libFuzzer requires nightly
```

Drive it from code:

```rust,no_run
use dev_fuzz::{FuzzBudget, FuzzRun};
use std::time::Duration;

let run = FuzzRun::new("parse_input", "0.1.0")
    .budget(FuzzBudget::time(Duration::from_secs(60)));
let result = run.execute()?;
let report = result.into_report();
println!("{}", report.to_json()?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Builder surface

| Method                              | What it does                                                     |
|-------------------------------------|------------------------------------------------------------------|
| `budget(FuzzBudget)`                | Time- or executions-based budget. Default: 60s wall-clock.       |
| `in_dir(path)`                      | Run `cargo fuzz` from a different directory.                     |
| `sanitizer(Sanitizer)`              | Pick `Address` / `Leak` / `Memory` / `Thread` / `None`. Default `Address`. |
| `timeout_per_iter(Duration)`        | libFuzzer's `-timeout=<secs>`.                                  |
| `rss_limit_mb(u32)`                 | libFuzzer's `-rss_limit_mb=<N>`.                                |
| `allow(name)` / `allow_all(iter)`   | Suppress findings whose reproducer basename matches.            |

## Budget types

| `FuzzBudget`         | Maps to libFuzzer flag       |
|----------------------|------------------------------|
| `time(Duration)`     | `-max_total_time=<secs>`     |
| `executions(u64)`    | `-runs=<N>`                  |

## Severity policy

| `FuzzFindingKind` | `dev-report::Severity` | `CheckResult` verdict |
|-------------------|------------------------|-----------------------|
| `Crash`           | `Critical`             | `Fail`                |
| `OutOfMemory`     | `Error`                | `Fail`                |
| `Timeout`         | `Warning`              | `Fail`                |

Each finding emits a `CheckResult` named
`fuzz::<target>::<kind-label>` (e.g. `fuzz::parse_input::crash`),
tagged `fuzz` plus the kind label (`crash` / `timeout` / `oom`).
The reproducer path rides along as `Evidence::FileRef` with the label
`"reproducer"`.

## Allow-listing known false positives

```rust,no_run
use dev_fuzz::{FuzzBudget, FuzzRun};
use std::time::Duration;

let run = FuzzRun::new("parse_input", "0.1.0")
    .budget(FuzzBudget::time(Duration::from_secs(60)))
    .allow("crash-known-false-positive")
    .allow_all(["crash-cafebabe", "timeout-known-slow"]);

let _result = run.execute()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Matches are on the *basename* of the reproducer path (the final
component, typically `crash-<hex>` or `timeout-<hex>`).

## `Producer` integration

`FuzzProducer` plugs the fuzz target into a multi-producer pipeline
driven by [`dev-tools`](https://github.com/jamesgober/dev-tools):

```rust,no_run
use dev_fuzz::{FuzzBudget, FuzzProducer, FuzzRun};
use dev_report::Producer;
use std::time::Duration;

let producer = FuzzProducer::new(
    FuzzRun::new("parse_input", "0.1.0")
        .budget(FuzzBudget::time(Duration::from_secs(60))),
);

let report = producer.produce();
println!("{}", report.to_json().unwrap());
```

Subprocess failures (missing tool, missing nightly, target not found,
libFuzzer harness error) map to a single failing `CheckResult` named
`fuzz::<target>` with `Severity::Critical` — the pipeline keeps
running.

## Wire format

`FuzzResult`, `FuzzFinding`, `FuzzFindingKind`, `FuzzBudget`, and
`Sanitizer` are all `serde`-derived. JSON uses `snake_case` field
names and `lowercase` enum variants:

```json
{
  "target": "parse_input",
  "version": "0.1.0",
  "executions": 1234567,
  "findings": [
    {
      "kind": "crash",
      "reproducer_path": "fuzz/artifacts/parse_input/crash-deadbeef",
      "summary": "thread '<unnamed>' panicked at 'assertion failed'"
    }
  ]
}
```

## Examples

| File                              | What it shows                                                |
|-----------------------------------|---------------------------------------------------------------|
| `examples/basic.rs`               | Default 10s budget; graceful tool-missing handling.          |
| `examples/executions_budget.rs`   | `FuzzBudget::executions(N)` instead of time.                 |
| `examples/with_limits.rs`         | Sanitizer choice, per-iter timeout, RSS limit, allow-list.   |
| `examples/producer.rs`            | `FuzzProducer` (gated by `DEV_FUZZ_EXAMPLE_RUN`).            |

## Requirements

Both prerequisites must be installed:

```bash
cargo install cargo-fuzz
rustup toolchain install nightly      # libFuzzer needs nightly
```

The crate detects absence of either and surfaces a typed `FuzzError`
variant rather than panicking.

Runtime dependency footprint: `dev-report`, `serde`, `serde_json`.

## Migration from `0.1.0`

`0.1.0` was a name-claim publish with a stub `execute()` returning an
empty result. Existing builder calls (`new`, `budget`, `execute`,
`into_report`) keep their signatures and behavior. New builder
methods (`in_dir`, `sanitizer`, `timeout_per_iter`, `rss_limit_mb`,
`allow`, `allow_all`) are additive.

## The `dev-*` suite

See [`dev-tools`](https://github.com/jamesgober/dev-tools) for the
umbrella crate covering the full suite.

## Status

`v0.9.x` is the pre-1.0 stabilization line. The crate is
feature-complete for libFuzzer-based fuzzing (subprocess invocation,
stderr parsing, severity policy, allow-list, sanitizer choice,
producer integration). `1.0` will pin the public API and the wire
format.

## Minimum supported Rust version

`1.85` for this crate. The *user's* fuzz targets require nightly
Rust because libFuzzer instrumentation is nightly-only — that's a
property of `cargo-fuzz`, not `dev-fuzz`.

## License

Apache-2.0. See [LICENSE](LICENSE).
