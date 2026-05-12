//! [`Producer`] integration: wrap a [`FuzzRun`] and emit a [`Report`]
//! every time the producer runs.
//!
//! [`Producer`]: dev_report::Producer
//! [`Report`]: dev_report::Report

use dev_report::{CheckResult, Producer, Report, Severity};

use crate::FuzzRun;

/// `Producer` adapter that drives a [`FuzzRun`] and converts the result
/// into a `Report`.
///
/// Subprocess failures (missing tool, missing nightly, target not
/// found, libFuzzer harness error) map to a single failing
/// `CheckResult` named `fuzz::<target>` with `Severity::Critical`. No
/// panics.
///
/// # Example
///
/// ```no_run
/// use dev_fuzz::{FuzzBudget, FuzzProducer, FuzzRun};
/// use dev_report::Producer;
/// use std::time::Duration;
///
/// let producer = FuzzProducer::new(
///     FuzzRun::new("parse_input", "0.1.0")
///         .budget(FuzzBudget::time(Duration::from_secs(60))),
/// );
/// let report = producer.produce();
/// println!("{}", report.to_json().unwrap());
/// ```
pub struct FuzzProducer {
    run: FuzzRun,
}

impl FuzzProducer {
    /// Build a producer that drives the given [`FuzzRun`].
    pub fn new(run: FuzzRun) -> Self {
        Self { run }
    }
}

impl Producer for FuzzProducer {
    fn produce(&self) -> Report {
        let target = self.run.target_name().to_string();
        let version = self.run.subject_version().to_string();
        let mut report = Report::new(&target, &version).with_producer("dev-fuzz");
        match self.run.execute() {
            Ok(result) => {
                let r = result.into_report();
                // `into_report` already populated `producer` and
                // started/finished times; replace `report` with the
                // result-derived one so we don't double-finish.
                return r;
            }
            Err(e) => {
                let detail = e.to_string();
                let check = CheckResult::fail(format!("fuzz::{target}"), Severity::Critical)
                    .with_detail(detail)
                    .with_tag("fuzz")
                    .with_tag("subprocess");
                report.push(check);
            }
        }
        report.finish();
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produce_returns_report_when_tool_missing() {
        // Default runner image won't have cargo-fuzz + nightly installed
        // alongside a fuzz target; the producer should surface that as
        // a failing CheckResult rather than panicking.
        let producer = FuzzProducer::new(FuzzRun::new("nonexistent_target", "0.0.0"));
        let report = producer.produce();
        assert_eq!(report.subject, "nonexistent_target");
        assert!(!report.checks.is_empty());
    }
}
