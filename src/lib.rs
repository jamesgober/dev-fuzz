//! # dev-fuzz
//!
//! Fuzzing harness integration for Rust. Part of the `dev-*`
//! verification suite.
//!
//! Wraps `cargo-fuzz` (libFuzzer-based) and emits findings as
//! `dev-report::Report`. Captures crashes, timeouts, and OOM events
//! with reproducer inputs attached.
//!
//! ## What is fuzzing?
//!
//! Fuzzing feeds random or guided-random inputs to your code looking
//! for crashes, panics, or unexpected behavior. It's especially
//! valuable for parsers, deserializers, network protocol handlers,
//! and anything that touches untrusted input.
//!
//! ## Quick example
//!
//! ```no_run
//! use dev_fuzz::{FuzzRun, FuzzBudget};
//! use std::time::Duration;
//!
//! let run = FuzzRun::new("parse_input", "0.1.0")
//!     .budget(FuzzBudget::time(Duration::from_secs(60)));
//! let result = run.execute().unwrap();
//! let report = result.into_report();
//! ```
//!
//! ## Status
//!
//! Pre-1.0. API shape defined; subprocess integration lands in `0.9.1`.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::time::Duration;

use dev_report::{CheckResult, Evidence, Report, Severity};

/// Type of finding discovered during a fuzz run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzFindingKind {
    /// A crash (panic, segfault, abort).
    Crash,
    /// An iteration exceeded the timeout.
    Timeout,
    /// An iteration exceeded the memory limit.
    OutOfMemory,
}

/// Budget for a fuzz run.
#[derive(Debug, Clone, Copy)]
pub enum FuzzBudget {
    /// Run for the given duration.
    Time(Duration),
    /// Run for the given number of executions.
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
}

/// Configuration for a fuzz run.
#[derive(Debug, Clone)]
pub struct FuzzRun {
    target: String,
    version: String,
    budget: FuzzBudget,
}

impl FuzzRun {
    /// Begin a new fuzz run against the given fuzz target.
    pub fn new(target: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            version: version.into(),
            budget: FuzzBudget::Time(Duration::from_secs(60)),
        }
    }

    /// Set the run budget.
    pub fn budget(mut self, budget: FuzzBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Selected budget.
    pub fn fuzz_budget(&self) -> FuzzBudget {
        self.budget
    }

    /// Execute the fuzz run.
    ///
    /// In `0.9.0` this is a stub; subprocess integration lands in `0.9.1`.
    pub fn execute(&self) -> Result<FuzzResult, FuzzError> {
        Ok(FuzzResult {
            target: self.target.clone(),
            version: self.version.clone(),
            executions: 0,
            findings: Vec::new(),
        })
    }
}

/// A single fuzz finding.
#[derive(Debug, Clone)]
pub struct FuzzFinding {
    /// Kind of finding.
    pub kind: FuzzFindingKind,
    /// Path to the input that triggered the finding (a "reproducer").
    pub reproducer_path: String,
    /// Short human-readable summary.
    pub summary: String,
}

/// Result of a fuzz run.
#[derive(Debug, Clone)]
pub struct FuzzResult {
    /// Fuzz target name.
    pub target: String,
    /// Crate version at the time of the run.
    pub version: String,
    /// Total executions completed.
    pub executions: u64,
    /// Findings discovered.
    pub findings: Vec<FuzzFinding>,
}

impl FuzzResult {
    /// Convert this result into a `dev-report::Report`.
    pub fn into_report(self) -> Report {
        let mut report = Report::new(&self.target, &self.version).with_producer("dev-fuzz");
        if self.findings.is_empty() {
            report.push(
                CheckResult::pass(format!("fuzz::{}", self.target))
                    .with_detail(format!("{} executions, 0 findings", self.executions))
                    .with_evidence(Evidence::numeric_int("executions", self.executions as i64)),
            );
        } else {
            for f in &self.findings {
                let sev = match f.kind {
                    FuzzFindingKind::Crash => Severity::Critical,
                    FuzzFindingKind::Timeout => Severity::Warning,
                    FuzzFindingKind::OutOfMemory => Severity::Error,
                };
                let kind_str = match f.kind {
                    FuzzFindingKind::Crash => "crash",
                    FuzzFindingKind::Timeout => "timeout",
                    FuzzFindingKind::OutOfMemory => "oom",
                };
                report.push(
                    CheckResult::fail(format!("fuzz::{}::{kind_str}", self.target), sev)
                        .with_detail(f.summary.clone())
                        .with_evidence(Evidence::file_ref("reproducer", &f.reproducer_path)),
                );
            }
        }
        report.finish();
        report
    }
}

/// Errors that can arise during a fuzz run.
#[derive(Debug)]
pub enum FuzzError {
    /// `cargo-fuzz` is not installed.
    ToolNotInstalled,
    /// Nightly Rust is required but not available.
    NightlyRequired,
    /// Subprocess failure.
    SubprocessFailed(String),
    /// The named fuzz target was not found in the project.
    TargetNotFound(String),
}

impl std::fmt::Display for FuzzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolNotInstalled => write!(f, "cargo-fuzz is not installed"),
            Self::NightlyRequired => write!(f, "nightly Rust is required"),
            Self::SubprocessFailed(s) => write!(f, "subprocess failed: {s}"),
            Self::TargetNotFound(s) => write!(f, "fuzz target not found: {s}"),
        }
    }
}

impl std::error::Error for FuzzError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_builds() {
        let r = FuzzRun::new("parse", "0.1.0");
        match r.fuzz_budget() {
            FuzzBudget::Time(_) => {}
            _ => panic!("default should be time-based"),
        }
    }

    #[test]
    fn executions_budget() {
        let r = FuzzRun::new("parse", "0.1.0").budget(FuzzBudget::executions(1_000_000));
        match r.fuzz_budget() {
            FuzzBudget::Executions(n) => assert_eq!(n, 1_000_000),
            _ => panic!("expected executions budget"),
        }
    }

    #[test]
    fn empty_findings_passes() {
        let r = FuzzResult {
            target: "parse".into(),
            version: "0.1.0".into(),
            executions: 1_000_000,
            findings: Vec::new(),
        };
        let report = r.into_report();
        assert!(report.passed());
    }

    #[test]
    fn crash_finding_is_critical() {
        let r = FuzzResult {
            target: "parse".into(),
            version: "0.1.0".into(),
            executions: 500,
            findings: vec![FuzzFinding {
                kind: FuzzFindingKind::Crash,
                reproducer_path: "fuzz/artifacts/crash-deadbeef".into(),
                summary: "panic in parse_input".into(),
            }],
        };
        let report = r.into_report();
        assert!(report.failed());
        assert_eq!(report.checks[0].severity, Some(Severity::Critical));
    }
}
