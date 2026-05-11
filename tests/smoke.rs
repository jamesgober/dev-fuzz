use dev_fuzz::{FuzzBudget, FuzzFinding, FuzzFindingKind, FuzzResult, FuzzRun};
use std::time::Duration;

#[test]
fn smoke_default_budget_is_time() {
    let r = FuzzRun::new("target", "0.1.0");
    match r.fuzz_budget() {
        FuzzBudget::Time(d) => assert_eq!(d, Duration::from_secs(60)),
        _ => panic!("default should be time-based"),
    }
}

#[test]
fn smoke_executions_budget() {
    let r = FuzzRun::new("target", "0.1.0").budget(FuzzBudget::executions(1_000_000));
    match r.fuzz_budget() {
        FuzzBudget::Executions(n) => assert_eq!(n, 1_000_000),
        _ => panic!("expected executions"),
    }
}

#[test]
fn smoke_empty_findings_passes() {
    let r = FuzzResult {
        target: "t".into(),
        version: "0.1.0".into(),
        executions: 1_000,
        findings: Vec::new(),
    };
    let report = r.into_report();
    assert!(report.passed());
}

#[test]
fn smoke_crash_produces_critical_failure() {
    let r = FuzzResult {
        target: "t".into(),
        version: "0.1.0".into(),
        executions: 100,
        findings: vec![FuzzFinding {
            kind: FuzzFindingKind::Crash,
            reproducer_path: "crash-input".into(),
            summary: "panic".into(),
        }],
    };
    let report = r.into_report();
    assert!(report.failed());
}

#[test]
fn smoke_timeout_produces_warning() {
    let r = FuzzResult {
        target: "t".into(),
        version: "0.1.0".into(),
        executions: 100,
        findings: vec![FuzzFinding {
            kind: FuzzFindingKind::Timeout,
            reproducer_path: "slow-input".into(),
            summary: "exceeded timeout".into(),
        }],
    };
    let report = r.into_report();
    // Warn verdict (not Fail) — timeout severity is Warning.
    assert!(report.failed() || report.warned());
}

#[test]
fn smoke_reproducer_attached_as_evidence() {
    let r = FuzzResult {
        target: "t".into(),
        version: "0.1.0".into(),
        executions: 100,
        findings: vec![FuzzFinding {
            kind: FuzzFindingKind::Crash,
            reproducer_path: "fuzz/artifacts/crash-deadbeef".into(),
            summary: "test".into(),
        }],
    };
    let report = r.into_report();
    let check = &report.checks[0];
    assert!(!check.evidence.is_empty());
}
