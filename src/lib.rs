//! # dev-fuzz
//!
//! Fuzzing harness integration for Rust. Wraps
//! [`cargo-fuzz`](https://crates.io/crates/cargo-fuzz) (libFuzzer-based)
//! and emits findings as [`dev_report::Report`].
//!
//! Captures crashes, timeouts, and OOM events with reproducer inputs
//! attached as [`Evidence::FileRef`](dev_report::Evidence) so consumers
//! can replay the input that triggered each finding.
//!
//! ## Quick example
//!
//! ```no_run
//! use dev_fuzz::{FuzzBudget, FuzzRun};
//! use std::time::Duration;
//!
//! let run = FuzzRun::new("parse_input", "0.1.0")
//!     .budget(FuzzBudget::time(Duration::from_secs(60)));
//! let result = run.execute().unwrap();
//! let report = result.into_report();
//! ```
//!
//! ## Requirements
//!
//! ```text
//! cargo install cargo-fuzz
//! rustup toolchain install nightly      # libFuzzer requires nightly
//! ```
//!
//! The crate detects absence of either prerequisite and surfaces
//! [`FuzzError::ToolNotInstalled`] / [`FuzzError::NightlyRequired`]
//! without panicking.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::path::PathBuf;
use std::time::Duration;

use dev_report::{CheckResult, Evidence, Report, Severity};
use serde::{Deserialize, Serialize};

mod producer;
mod runner;

pub use producer::FuzzProducer;

// ---------------------------------------------------------------------------
// FuzzFindingKind
// ---------------------------------------------------------------------------

/// Type of finding discovered during a fuzz run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FuzzFindingKind {
    /// A crash (panic, signal, libFuzzer "deadly signal").
    Crash,
    /// libFuzzer reported the input exceeded the per-execution timeout.
    Timeout,
    /// libFuzzer reported the input exceeded the configured memory limit.
    OutOfMemory,
}

impl FuzzFindingKind {
    /// Severity mapped from this finding kind per REPS § 3.
    pub fn severity(self) -> Severity {
        match self {
            Self::Crash => Severity::Critical,
            Self::OutOfMemory => Severity::Error,
            Self::Timeout => Severity::Warning,
        }
    }

    /// Lowercase short label (`crash`, `timeout`, `oom`). Stable: used
    /// in `CheckResult` names and is suitable for log / metric keys.
    pub fn label(self) -> &'static str {
        match self {
            Self::Crash => "crash",
            Self::Timeout => "timeout",
            Self::OutOfMemory => "oom",
        }
    }
}

// ---------------------------------------------------------------------------
// FuzzBudget
// ---------------------------------------------------------------------------

/// Budget for a fuzz run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzBudget {
    /// Run for the given wall-clock duration. Translates to
    /// `-max_total_time=<secs>` on the libFuzzer side.
    Time(Duration),
    /// Run for the given number of executions. Translates to
    /// `-runs=<N>` on the libFuzzer side.
    Executions(u64),
}

impl FuzzBudget {
    /// Build a time-based budget.
    pub fn time(d: Duration) -> Self {
        Self::Time(d)
    }

    /// Build an execution-count budget.
    pub fn executions(n: u64) -> Self {
        Self::Executions(n)
    }

    /// libFuzzer-style flag suffix for this budget.
    pub(crate) fn as_libfuzzer_flag(&self) -> String {
        match self {
            Self::Time(d) => format!("-max_total_time={}", d.as_secs().max(1)),
            Self::Executions(n) => format!("-runs={}", n),
        }
    }
}

// ---------------------------------------------------------------------------
// Sanitizer
// ---------------------------------------------------------------------------

/// Which sanitizer to enable on the fuzz target build.
///
/// `cargo-fuzz` accepts `address`, `leak`, `memory`, `thread`,
/// `none`. We expose the most common four.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sanitizer {
    /// AddressSanitizer (default in `cargo-fuzz`).
    Address,
    /// LeakSanitizer.
    Leak,
    /// MemorySanitizer.
    Memory,
    /// ThreadSanitizer.
    Thread,
    /// No sanitizer (faster, less informative).
    None,
}

impl Sanitizer {
    pub(crate) fn as_cargo_fuzz_flag(self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::Leak => "leak",
            Self::Memory => "memory",
            Self::Thread => "thread",
            Self::None => "none",
        }
    }
}

// ---------------------------------------------------------------------------
// FuzzRun
// ---------------------------------------------------------------------------

/// Configuration for a fuzz run.
///
/// # Example
///
/// ```no_run
/// use dev_fuzz::{FuzzBudget, FuzzRun, Sanitizer};
/// use std::time::Duration;
///
/// let run = FuzzRun::new("parse_input", "0.1.0")
///     .budget(FuzzBudget::time(Duration::from_secs(60)))
///     .sanitizer(Sanitizer::Address)
///     .timeout_per_iter(Duration::from_secs(5))
///     .rss_limit_mb(2048);
///
/// let _result = run.execute().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct FuzzRun {
    target: String,
    version: String,
    budget: FuzzBudget,
    workdir: Option<PathBuf>,
    sanitizer: Sanitizer,
    timeout_per_iter: Option<Duration>,
    rss_limit_mb: Option<u32>,
    allow_list: Vec<String>,
}

impl FuzzRun {
    /// Begin a new fuzz run against the given fuzz target.
    ///
    /// `target` is the libFuzzer target name (the file under
    /// `fuzz/fuzz_targets/<target>.rs`). `version` is descriptive and
    /// flows into the produced `Report`.
    pub fn new(target: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            version: version.into(),
            budget: FuzzBudget::Time(Duration::from_secs(60)),
            workdir: None,
            sanitizer: Sanitizer::Address,
            timeout_per_iter: None,
            rss_limit_mb: None,
            allow_list: Vec::new(),
        }
    }

    /// Set the run budget. Default: 60 seconds of wall-clock time.
    pub fn budget(mut self, budget: FuzzBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Selected budget.
    pub fn fuzz_budget(&self) -> FuzzBudget {
        self.budget
    }

    /// Run `cargo fuzz` from `dir` instead of the current directory.
    pub fn in_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.workdir = Some(dir.into());
        self
    }

    /// Pick the sanitizer to enable. Default: `Sanitizer::Address`.
    pub fn sanitizer(mut self, sanitizer: Sanitizer) -> Self {
        self.sanitizer = sanitizer;
        self
    }

    /// Per-iteration timeout. Translates to libFuzzer's `-timeout=<secs>`.
    pub fn timeout_per_iter(mut self, d: Duration) -> Self {
        self.timeout_per_iter = Some(d);
        self
    }

    /// Per-iteration RSS limit, in megabytes. Translates to libFuzzer's
    /// `-rss_limit_mb=<N>`.
    pub fn rss_limit_mb(mut self, mb: u32) -> Self {
        self.rss_limit_mb = Some(mb);
        self
    }

    /// Suppress a finding whose reproducer-path basename matches `name`.
    ///
    /// Useful for known false positives that have a triaged reproducer
    /// already on disk (e.g. `crash-deadbeef`). The match is on the
    /// final path component only.
    pub fn allow(mut self, name: impl Into<String>) -> Self {
        self.allow_list.push(name.into());
        self
    }

    /// Bulk version of [`allow`](Self::allow).
    pub fn allow_all<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allow_list.extend(names.into_iter().map(Into::into));
        self
    }

    /// Target name (the `fuzz_targets/<name>.rs` file).
    pub fn target_name(&self) -> &str {
        &self.target
    }

    /// Descriptive subject version.
    pub fn subject_version(&self) -> &str {
        &self.version
    }

    /// Execute the fuzz run.
    ///
    /// Spawns `cargo +nightly fuzz run <target>` with the configured
    /// budget, sanitizer, and limits. Captures stderr (where libFuzzer
    /// writes its findings) and parses out crash / timeout / OOM
    /// records with reproducer paths.
    ///
    /// Tool / nightly / target-not-found preconditions surface as
    /// typed [`FuzzError`] variants. No panics.
    pub fn execute(&self) -> Result<FuzzResult, FuzzError> {
        runner::run(self)
    }

    pub(crate) fn workdir_path(&self) -> Option<&std::path::Path> {
        self.workdir.as_deref()
    }

    pub(crate) fn sanitizer_kind(&self) -> Sanitizer {
        self.sanitizer
    }

    pub(crate) fn timeout_per_iter_value(&self) -> Option<Duration> {
        self.timeout_per_iter
    }

    pub(crate) fn rss_limit_value(&self) -> Option<u32> {
        self.rss_limit_mb
    }

    pub(crate) fn allow_list_view(&self) -> &[String] {
        &self.allow_list
    }
}

// ---------------------------------------------------------------------------
// FuzzFinding + FuzzResult
// ---------------------------------------------------------------------------

/// A single fuzz finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzFinding {
    /// Kind of finding (crash / timeout / OOM).
    pub kind: FuzzFindingKind,
    /// Path to the input that triggered the finding ("reproducer").
    pub reproducer_path: String,
    /// Short human-readable summary captured from libFuzzer's output.
    pub summary: String,
}

/// Result of a fuzz run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    /// Fuzz target name.
    pub target: String,
    /// Subject version (descriptive).
    pub version: String,
    /// Total executions completed by libFuzzer.
    pub executions: u64,
    /// Findings discovered during the run.
    pub findings: Vec<FuzzFinding>,
}

impl FuzzResult {
    /// Total number of findings.
    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }

    /// Number of findings whose [`kind`](FuzzFinding::kind) equals `kind`.
    pub fn count_of(&self, kind: FuzzFindingKind) -> usize {
        self.findings.iter().filter(|f| f.kind == kind).count()
    }

    /// Highest severity present across findings, if any.
    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings
            .iter()
            .map(|f| f.kind.severity())
            .max_by_key(|s| severity_ord(*s))
    }

    /// Convert into a [`Report`].
    ///
    /// No findings → one passing `CheckResult` named
    /// `fuzz::<target>` with `executions` numeric evidence. Otherwise
    /// one failing `CheckResult` per finding named
    /// `fuzz::<target>::<kind>` tagged `fuzz` plus a kind-specific tag
    /// (`crash`, `timeout`, `oom`). Each finding's reproducer path
    /// rides along as `Evidence::FileRef`.
    pub fn into_report(self) -> Report {
        let mut report = Report::new(&self.target, &self.version).with_producer("dev-fuzz");
        if self.findings.is_empty() {
            report.push(
                CheckResult::pass(format!("fuzz::{}", self.target))
                    .with_tag("fuzz")
                    .with_detail(format!("{} executions, 0 findings", self.executions))
                    .with_evidence(Evidence::numeric_int("executions", self.executions as i64)),
            );
        } else {
            for f in &self.findings {
                let sev = f.kind.severity();
                let check =
                    CheckResult::fail(format!("fuzz::{}::{}", self.target, f.kind.label()), sev)
                        .with_detail(f.summary.clone())
                        .with_tag("fuzz")
                        .with_tag(f.kind.label())
                        .with_evidence(Evidence::file_ref("reproducer", &f.reproducer_path));
                report.push(check);
            }
        }
        report.finish();
        report
    }
}

pub(crate) fn severity_ord(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}

// ---------------------------------------------------------------------------
// FuzzError
// ---------------------------------------------------------------------------

/// Errors that can arise during a fuzz run.
#[derive(Debug)]
pub enum FuzzError {
    /// `cargo-fuzz` is not installed on the system.
    ToolNotInstalled,
    /// The nightly Rust toolchain is required but not installed.
    NightlyRequired,
    /// Subprocess returned a fatal error (non-zero exit with no
    /// recoverable output).
    SubprocessFailed(String),
    /// The named fuzz target was not found in the project.
    TargetNotFound(String),
}

impl std::fmt::Display for FuzzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolNotInstalled => write!(
                f,
                "cargo-fuzz is not installed; run `cargo install cargo-fuzz`"
            ),
            Self::NightlyRequired => write!(
                f,
                "nightly Rust required; run `rustup toolchain install nightly`"
            ),
            Self::SubprocessFailed(s) => write!(f, "cargo fuzz failed: {s}"),
            Self::TargetNotFound(s) => write!(f, "fuzz target not found: {s}"),
        }
    }
}

impl std::error::Error for FuzzError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_kind_severity_mapping_matches_reps() {
        assert_eq!(FuzzFindingKind::Crash.severity(), Severity::Critical);
        assert_eq!(FuzzFindingKind::OutOfMemory.severity(), Severity::Error);
        assert_eq!(FuzzFindingKind::Timeout.severity(), Severity::Warning);
    }

    #[test]
    fn finding_kind_labels_are_stable() {
        assert_eq!(FuzzFindingKind::Crash.label(), "crash");
        assert_eq!(FuzzFindingKind::OutOfMemory.label(), "oom");
        assert_eq!(FuzzFindingKind::Timeout.label(), "timeout");
    }

    #[test]
    fn budget_as_libfuzzer_flag() {
        assert_eq!(
            FuzzBudget::time(Duration::from_secs(60)).as_libfuzzer_flag(),
            "-max_total_time=60"
        );
        assert_eq!(
            FuzzBudget::time(Duration::from_millis(500)).as_libfuzzer_flag(),
            "-max_total_time=1"
        );
        assert_eq!(
            FuzzBudget::executions(1_000_000).as_libfuzzer_flag(),
            "-runs=1000000"
        );
    }

    #[test]
    fn sanitizer_flag_values() {
        assert_eq!(Sanitizer::Address.as_cargo_fuzz_flag(), "address");
        assert_eq!(Sanitizer::Leak.as_cargo_fuzz_flag(), "leak");
        assert_eq!(Sanitizer::Memory.as_cargo_fuzz_flag(), "memory");
        assert_eq!(Sanitizer::Thread.as_cargo_fuzz_flag(), "thread");
        assert_eq!(Sanitizer::None.as_cargo_fuzz_flag(), "none");
    }

    #[test]
    fn run_builder_chains() {
        let run = FuzzRun::new("parse", "0.1.0")
            .budget(FuzzBudget::time(Duration::from_secs(30)))
            .sanitizer(Sanitizer::Memory)
            .timeout_per_iter(Duration::from_secs(5))
            .rss_limit_mb(2048)
            .allow("crash-deadbeef")
            .allow_all(["crash-cafebabe", "timeout-abc"]);
        assert_eq!(run.target_name(), "parse");
        assert_eq!(run.subject_version(), "0.1.0");
        assert_eq!(run.sanitizer_kind(), Sanitizer::Memory);
        assert_eq!(run.rss_limit_value(), Some(2048));
        assert_eq!(run.allow_list_view().len(), 3);
    }

    #[test]
    fn empty_findings_passes_with_executions_evidence() {
        let r = FuzzResult {
            target: "parse".into(),
            version: "0.1.0".into(),
            executions: 1_000_000,
            findings: Vec::new(),
        };
        let report = r.into_report();
        assert!(report.passed());
        assert_eq!(report.checks.len(), 1);
        let c = &report.checks[0];
        assert!(c.has_tag("fuzz"));
        assert!(c.evidence.iter().any(|e| e.label == "executions"));
    }

    #[test]
    fn crash_finding_is_critical() {
        let r = FuzzResult {
            target: "parse".into(),
            version: "0.1.0".into(),
            executions: 500,
            findings: vec![FuzzFinding {
                kind: FuzzFindingKind::Crash,
                reproducer_path: "fuzz/artifacts/parse/crash-deadbeef".into(),
                summary: "panic in parse_input".into(),
            }],
        };
        let report = r.into_report();
        assert!(report.failed());
        assert_eq!(report.checks[0].severity, Some(Severity::Critical));
        assert!(report.checks[0].has_tag("crash"));
    }

    #[test]
    fn each_kind_produces_one_check() {
        let r = FuzzResult {
            target: "p".into(),
            version: "0.1.0".into(),
            executions: 10,
            findings: vec![
                FuzzFinding {
                    kind: FuzzFindingKind::Crash,
                    reproducer_path: "a".into(),
                    summary: "x".into(),
                },
                FuzzFinding {
                    kind: FuzzFindingKind::OutOfMemory,
                    reproducer_path: "b".into(),
                    summary: "x".into(),
                },
                FuzzFinding {
                    kind: FuzzFindingKind::Timeout,
                    reproducer_path: "c".into(),
                    summary: "x".into(),
                },
            ],
        };
        let report = r.into_report();
        assert_eq!(report.checks.len(), 3);
        assert!(report
            .checks
            .iter()
            .any(|c| c.severity == Some(Severity::Critical)));
        assert!(report
            .checks
            .iter()
            .any(|c| c.severity == Some(Severity::Error)));
        assert!(report
            .checks
            .iter()
            .any(|c| c.severity == Some(Severity::Warning)));
    }

    #[test]
    fn count_of_filters_by_kind() {
        let r = FuzzResult {
            target: "p".into(),
            version: "0.1.0".into(),
            executions: 0,
            findings: vec![
                FuzzFinding {
                    kind: FuzzFindingKind::Crash,
                    reproducer_path: "a".into(),
                    summary: "x".into(),
                },
                FuzzFinding {
                    kind: FuzzFindingKind::Crash,
                    reproducer_path: "b".into(),
                    summary: "x".into(),
                },
                FuzzFinding {
                    kind: FuzzFindingKind::Timeout,
                    reproducer_path: "c".into(),
                    summary: "x".into(),
                },
            ],
        };
        assert_eq!(r.count_of(FuzzFindingKind::Crash), 2);
        assert_eq!(r.count_of(FuzzFindingKind::Timeout), 1);
        assert_eq!(r.count_of(FuzzFindingKind::OutOfMemory), 0);
        assert_eq!(r.total_findings(), 3);
    }

    #[test]
    fn worst_severity_picks_max() {
        let r = FuzzResult {
            target: "p".into(),
            version: "0.1.0".into(),
            executions: 0,
            findings: vec![
                FuzzFinding {
                    kind: FuzzFindingKind::Timeout,
                    reproducer_path: "a".into(),
                    summary: "x".into(),
                },
                FuzzFinding {
                    kind: FuzzFindingKind::Crash,
                    reproducer_path: "b".into(),
                    summary: "x".into(),
                },
            ],
        };
        assert_eq!(r.worst_severity(), Some(Severity::Critical));
        let empty = FuzzResult {
            target: "p".into(),
            version: "0.1.0".into(),
            executions: 0,
            findings: Vec::new(),
        };
        assert_eq!(empty.worst_severity(), None);
    }

    #[test]
    fn result_round_trips_through_json() {
        let r = FuzzResult {
            target: "parse".into(),
            version: "0.1.0".into(),
            executions: 1234,
            findings: vec![FuzzFinding {
                kind: FuzzFindingKind::Crash,
                reproducer_path: "fuzz/artifacts/parse/crash-1".into(),
                summary: "panicked".into(),
            }],
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: FuzzResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.findings[0].kind, FuzzFindingKind::Crash);
    }
}
