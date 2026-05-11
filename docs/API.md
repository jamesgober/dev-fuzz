# dev-fuzz — API Reference

> Hand-written reference. Mirrors `cargo doc --open` output with
> curated examples and structure.

## Table of contents

- [`FuzzFindingKind`](#fuzzfindingkind)
  - [`FuzzFindingKind::Crash`](#fuzzfindingkindcrash)
  - [`FuzzFindingKind::Timeout`](#fuzzfindingkindtimeout)
  - [`FuzzFindingKind::OutOfMemory`](#fuzzfindingkindoutofmemory)
- [`FuzzBudget`](#fuzzbudget)
  - [`FuzzBudget::time`](#fuzzbudgettime)
  - [`FuzzBudget::executions`](#fuzzbudgetexecutions)
- [`FuzzRun`](#fuzzrun)
  - [`FuzzRun::new`](#fuzzrunnew)
  - [`FuzzRun::budget`](#fuzzrunbudget)
  - [`FuzzRun::fuzz_budget`](#fuzzrunfuzz_budget)
  - [`FuzzRun::execute`](#fuzzrunexecute)
- [`FuzzFinding`](#fuzzfinding)
- [`FuzzResult`](#fuzzresult)
  - [Fields](#fuzzresult-fields)
  - [`FuzzResult::into_report`](#fuzzresultinto_report)
- [`FuzzError`](#fuzzerror)

---

## `FuzzFindingKind`

```rust
pub enum FuzzFindingKind {
    Crash,
    Timeout,
    OutOfMemory,
}
```

Type of finding discovered during a fuzz run.

### `FuzzFindingKind::Crash`

A crash (panic, segfault, abort). Mapped to `Severity::Critical`.

### `FuzzFindingKind::Timeout`

A single iteration exceeded its timeout. Mapped to
`Severity::Warning`. Timeouts often indicate algorithmic problems
(infinite loops, pathological inputs) rather than memory-safety bugs.

### `FuzzFindingKind::OutOfMemory`

An iteration exceeded the memory limit. Mapped to `Severity::Error`.

---

## `FuzzBudget`

```rust
pub enum FuzzBudget {
    Time(Duration),
    Executions(u64),
}
```

How long a fuzz run should continue.

### `FuzzBudget::time`

```rust
pub fn time(d: Duration) -> Self
```

Build a time-based budget.

```rust
use dev_fuzz::FuzzBudget;
use std::time::Duration;

let b = FuzzBudget::time(Duration::from_secs(60));
```

### `FuzzBudget::executions`

```rust
pub fn executions(n: u64) -> Self
```

Build an execution-count budget.

```rust
use dev_fuzz::FuzzBudget;

let b = FuzzBudget::executions(1_000_000);
```

---

## `FuzzRun`

```rust
pub struct FuzzRun { /* private */ }
```

### `FuzzRun::new`

```rust
pub fn new(target: impl Into<String>, version: impl Into<String>) -> Self
```

| Parameter | Type                | Description                                  |
|-----------|---------------------|----------------------------------------------|
| `target`  | `impl Into<String>` | Fuzz target name (matches `fuzz/fuzz_targets/*.rs`). |
| `version` | `impl Into<String>` | Crate version at time of run.                |

```rust
use dev_fuzz::FuzzRun;

let run = FuzzRun::new("parse_input", "0.1.0");
```

### `FuzzRun::budget`

```rust
pub fn budget(self, budget: FuzzBudget) -> Self
```

Set the run budget. Default is `FuzzBudget::Time(60s)`.

### `FuzzRun::fuzz_budget`

```rust
pub fn fuzz_budget(&self) -> FuzzBudget
```

Return the configured budget.

### `FuzzRun::execute`

```rust
pub fn execute(&self) -> Result<FuzzResult, FuzzError>
```

Run the fuzz target. Returns:
- `Ok(FuzzResult)` on completion (including completion with findings).
- `Err(FuzzError::ToolNotInstalled)` if `cargo-fuzz` is missing.
- `Err(FuzzError::NightlyRequired)` if nightly Rust is unavailable.
- `Err(FuzzError::TargetNotFound)` if the named target doesn't exist.
- `Err(FuzzError::SubprocessFailed)` for other subprocess failures.

---

## `FuzzFinding`

```rust
pub struct FuzzFinding {
    pub kind: FuzzFindingKind,
    pub reproducer_path: String,
    pub summary: String,
}
```

A single finding. Every finding MUST have a `reproducer_path`
pointing at the input that triggered it, so the issue can be
replayed and debugged.

---

## `FuzzResult`

```rust
pub struct FuzzResult {
    pub target: String,
    pub version: String,
    pub executions: u64,
    pub findings: Vec<FuzzFinding>,
}
```

### FuzzResult fields

| Field        | Type                | Description                                   |
|--------------|---------------------|-----------------------------------------------|
| `target`     | `String`            | Fuzz target name.                             |
| `version`    | `String`            | Crate version.                                |
| `executions` | `u64`               | Total iterations the fuzzer ran.              |
| `findings`   | `Vec<FuzzFinding>`  | Findings discovered.                          |

### `FuzzResult::into_report`

```rust
pub fn into_report(self) -> Report
```

Convert this result into a `dev-report::Report`. Empty findings
produces a passing `fuzz::<target>` check with execution count
attached as `Evidence::Numeric`. Each finding produces a separate
fail-verdict check with the reproducer attached as
`Evidence::FileRef`.

---

## `FuzzError`

```rust
pub enum FuzzError {
    ToolNotInstalled,
    NightlyRequired,
    SubprocessFailed(String),
    TargetNotFound(String),
}
```

| Variant                | Remediation                                          |
|------------------------|------------------------------------------------------|
| `ToolNotInstalled`     | `cargo install cargo-fuzz`                           |
| `NightlyRequired`      | `rustup toolchain install nightly`                   |
| `SubprocessFailed(s)`  | Inspect `s` for the underlying error.                |
| `TargetNotFound(s)`    | Create `fuzz/fuzz_targets/s.rs` or check the name.   |
