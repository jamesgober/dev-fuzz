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
</p>

<p align="center">
    Captures crashes, timeouts, and OOM events with reproducer inputs.<br>
    Part of the <code>dev-*</code> verification suite.
</p>

---

## What it does

`dev-fuzz` wraps `cargo-fuzz` (libFuzzer-based) and emits findings as
`dev-report::Report`. Each finding carries a reproducer path so the
crash can be replayed and debugged.

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

```rust
use dev_fuzz::{FuzzRun, FuzzBudget};
use std::time::Duration;

let run = FuzzRun::new("parse_input", "0.1.0")
    .budget(FuzzBudget::time(Duration::from_secs(60)));
let result = run.execute()?;
let report = result.into_report();
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Requirements

```bash
cargo install cargo-fuzz
```

`cargo-fuzz` requires nightly Rust. The crate detects that and emits
a clear `FuzzError::NightlyRequired` if it's missing.

## Budget types

| Budget                       | Description                                  |
|------------------------------|----------------------------------------------|
| `FuzzBudget::Time`           | Run for the given duration.                  |
| `FuzzBudget::Executions`     | Run for the given number of executions.      |

## Finding severities

| Finding kind      | Severity              |
|-------------------|-----------------------|
| `Crash`           | `Critical`            |
| `OutOfMemory`     | `Error`               |
| `Timeout`         | `Warning`             |

Each finding's reproducer path is attached as `Evidence::FileRef` so
consumers can replay the input.

## The `dev-*` suite

See [`dev-tools`](https://github.com/jamesgober/dev-tools) for the
full suite.

## Status

`v0.9.0` is the foundation release: API shape defined, subprocess
integration lands in `0.9.1`. Production use is discouraged until
`1.0`.

## Minimum supported Rust version

`1.85` for this crate; the *user's* fuzz targets require nightly Rust
(driven by `cargo-fuzz`).

## License

Apache-2.0. See [LICENSE](LICENSE).
