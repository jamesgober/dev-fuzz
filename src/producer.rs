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
    use dev_report::Verdict;

    #[test]
    fn produce_maps_run_failure_to_critical_fail() {
        // An empty directory has no fuzz/ project, so the run fails fast
        // whichever prerequisite is missing first (cargo-fuzz, nightly,
        // or the target itself).
        let dir = tempfile::tempdir().unwrap();
        let producer =
            FuzzProducer::new(FuzzRun::new("nonexistent_target", "0.0.0").in_dir(dir.path()));
        let report = producer.produce();
        assert_eq!(report.subject, "nonexistent_target");
        assert_eq!(report.checks.len(), 1);
        let check = &report.checks[0];
        assert_eq!(check.name, "fuzz::nonexistent_target");
        assert_eq!(check.verdict, Verdict::Fail);
        assert_eq!(check.severity, Some(Severity::Critical));
        assert!(check.has_tag("subprocess"));
    }

    #[test]
    fn produce_maps_missing_workdir_to_critical_fail() {
        let producer =
            FuzzProducer::new(FuzzRun::new("parse", "0.0.0").in_dir("definitely/not/a/dir/7f3a"));
        let report = producer.produce();
        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.checks[0].verdict, Verdict::Fail);
        assert!(report.checks[0]
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("does not exist"));
    }
}
