//! `cargo fuzz` subprocess invocation + libFuzzer stderr parser.
//!
//! libFuzzer writes its output to stderr. The shapes we care about:
//!
//! ```text
//! ==1234== ERROR: libFuzzer: deadly signal
//!   ... (panic / signal details) ...
//! SUMMARY: libFuzzer: deadly signal
//! artifact_prefix='./fuzz/artifacts/parse/'; Test unit written to ./fuzz/artifacts/parse/crash-deadbeef
//! ```
//!
//! Timeout / OOM variants use `SUMMARY: libFuzzer: timeout` and
//! `SUMMARY: libFuzzer: out-of-memory` respectively. The "Test unit
//! written to <path>" line is the reproducer path we surface.
//!
//! Execution counts come from libFuzzer's periodic status lines:
//! `#1234567` style entries; we take the highest seen as the
//! `executions` count.

use std::path::Path;
use std::process::Command;

use crate::{FuzzError, FuzzFinding, FuzzFindingKind, FuzzResult, FuzzRun};

pub(crate) fn run(cfg: &FuzzRun) -> Result<FuzzResult, FuzzError> {
    detect_cargo_fuzz()?;
    detect_nightly()?;
    ensure_target_exists(cfg)?;

    let output = run_cargo_fuzz(cfg)?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

    let mut findings = parse_findings(&stderr);
    apply_allow_list(&mut findings, cfg.allow_list_view());
    let executions = parse_executions(&stderr)
        .or_else(|| parse_executions(&stdout))
        .unwrap_or(0);

    // If cargo-fuzz exited non-zero but we didn't extract a finding,
    // surface the stderr so the user sees what went wrong rather than
    // a silent empty result.
    if !output.status.success() && findings.is_empty() {
        return Err(FuzzError::SubprocessFailed(stderr));
    }

    Ok(FuzzResult {
        target: cfg.target_name().to_string(),
        version: cfg.subject_version().to_string(),
        executions,
        findings,
    })
}

fn detect_cargo_fuzz() -> Result<(), FuzzError> {
    let probe = Command::new("cargo").args(["fuzz", "--version"]).output();
    match probe {
        Ok(o) if o.status.success() => Ok(()),
        _ => Err(FuzzError::ToolNotInstalled),
    }
}

fn detect_nightly() -> Result<(), FuzzError> {
    let probe = Command::new("rustup").args(["toolchain", "list"]).output();
    match probe {
        Ok(o) if o.status.success() => {
            let listing = String::from_utf8_lossy(&o.stdout);
            if listing.lines().any(|l| l.starts_with("nightly")) {
                Ok(())
            } else {
                Err(FuzzError::NightlyRequired)
            }
        }
        // No rustup at all is also a "nightly is missing" condition.
        _ => Err(FuzzError::NightlyRequired),
    }
}

fn ensure_target_exists(cfg: &FuzzRun) -> Result<(), FuzzError> {
    let mut cmd = Command::new("cargo");
    cmd.args(["fuzz", "list"]);
    if let Some(dir) = cfg.workdir_path() {
        cmd.current_dir(dir);
    }
    let output = match cmd.output() {
        Ok(o) => o,
        Err(_) => return Ok(()), // can't list; let the run itself surface the error
    };
    if !output.status.success() {
        // `cargo fuzz list` failing is itself usually a "no fuzz/ dir"
        // condition. Let `run` surface a more informative error.
        return Ok(());
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    let found = listing
        .lines()
        .map(|l| l.trim())
        .any(|l| !l.is_empty() && l == cfg.target_name());
    if found {
        Ok(())
    } else {
        Err(FuzzError::TargetNotFound(cfg.target_name().to_string()))
    }
}

fn run_cargo_fuzz(cfg: &FuzzRun) -> Result<std::process::Output, FuzzError> {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "+nightly",
        "fuzz",
        "run",
        "--sanitizer",
        cfg.sanitizer_kind().as_cargo_fuzz_flag(),
        cfg.target_name(),
        "--",
    ]);
    cmd.arg(cfg.fuzz_budget().as_libfuzzer_flag());
    if let Some(t) = cfg.timeout_per_iter_value() {
        cmd.arg(format!("-timeout={}", t.as_secs().max(1)));
    }
    if let Some(mb) = cfg.rss_limit_value() {
        cmd.arg(format!("-rss_limit_mb={}", mb));
    }
    if let Some(dir) = cfg.workdir_path() {
        cmd.current_dir(dir);
    }
    cmd.output()
        .map_err(|e| FuzzError::SubprocessFailed(e.to_string()))
}

fn apply_allow_list(findings: &mut Vec<FuzzFinding>, allow_list: &[String]) {
    if allow_list.is_empty() {
        return;
    }
    findings.retain(|f| {
        let basename = Path::new(&f.reproducer_path)
            .file_name()
            .and_then(|os| os.to_str())
            .unwrap_or(&f.reproducer_path);
        !allow_list.iter().any(|n| n == basename)
    });
}

// ---------------------------------------------------------------------------
// Stderr parser
// ---------------------------------------------------------------------------

pub(crate) fn parse_findings(stderr: &str) -> Vec<FuzzFinding> {
    let mut out = Vec::new();
    // Walk forward; whenever we see a SUMMARY line, look ahead for the
    // matching "Test unit written to" line that libFuzzer emits
    // immediately afterwards. Collect (kind, summary, reproducer_path)
    // tuples.
    let lines: Vec<&str> = stderr.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let kind = match summary_kind(line) {
            Some(k) => k,
            None => continue,
        };
        // Look back a few lines for a more descriptive line if available.
        let summary = previous_descriptive_line(&lines, i)
            .unwrap_or(line)
            .to_string();
        let reproducer_path = reproducer_path_after(&lines, i)
            .unwrap_or_else(|| format!("<unknown reproducer for {}>", kind.label()));
        out.push(FuzzFinding {
            kind,
            reproducer_path,
            summary,
        });
    }
    out
}

fn summary_kind(line: &str) -> Option<FuzzFindingKind> {
    let l = line.trim();
    if !l.starts_with("SUMMARY: libFuzzer:") {
        return None;
    }
    let rest = l.trim_start_matches("SUMMARY: libFuzzer:").trim();
    if rest.starts_with("timeout") {
        Some(FuzzFindingKind::Timeout)
    } else if rest.starts_with("out-of-memory") {
        Some(FuzzFindingKind::OutOfMemory)
    } else {
        // Everything else from libFuzzer (deadly signal, fuzz target
        // exited, libFuzzer triple, etc.) maps to Crash.
        Some(FuzzFindingKind::Crash)
    }
}

fn previous_descriptive_line<'a>(lines: &'a [&'a str], i: usize) -> Option<&'a str> {
    // Walk a few lines backwards and pick the first ERROR / panic line.
    for line in lines[..i].iter().rev().take(20) {
        let t = line.trim();
        if t.starts_with("==") && t.contains("ERROR: libFuzzer:") {
            return Some(t);
        }
        if t.starts_with("thread '") && t.contains("panicked at") {
            return Some(t);
        }
        if t.starts_with("ERROR:") {
            return Some(t);
        }
    }
    None
}

fn reproducer_path_after(lines: &[&str], i: usize) -> Option<String> {
    for line in lines.iter().skip(i + 1).take(10) {
        let t = line.trim();
        if let Some(p) = extract_reproducer_path(t) {
            return Some(p);
        }
    }
    // libFuzzer occasionally emits the path BEFORE the SUMMARY line.
    for line in lines[..i].iter().rev().take(20) {
        let t = line.trim();
        if let Some(p) = extract_reproducer_path(t) {
            return Some(p);
        }
    }
    None
}

fn extract_reproducer_path(line: &str) -> Option<String> {
    let marker = "Test unit written to ";
    let idx = line.find(marker)?;
    let after = &line[idx + marker.len()..];
    // Path runs until end of line; libFuzzer doesn't quote it.
    let path = after.trim();
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

pub(crate) fn parse_executions(stderr: &str) -> Option<u64> {
    // libFuzzer status lines start with `#N ...`. Pick the highest N.
    let mut max_exec: Option<u64> = None;
    for line in stderr.lines() {
        let t = line.trim_start();
        if !t.starts_with('#') {
            continue;
        }
        let rest = &t[1..];
        let n_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if n_str.is_empty() {
            continue;
        }
        if let Ok(n) = n_str.parse::<u64>() {
            max_exec = Some(max_exec.map_or(n, |prev| prev.max(n)));
        }
    }
    max_exec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_deadly_signal_crash() {
        let stderr = concat!(
            "==1234== ERROR: libFuzzer: deadly signal\n",
            "  some backtrace\n",
            "SUMMARY: libFuzzer: deadly signal\n",
            "artifact_prefix='./fuzz/artifacts/parse/'; Test unit written to ./fuzz/artifacts/parse/crash-deadbeef\n",
        );
        let findings = parse_findings(stderr);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::Crash);
        assert_eq!(
            findings[0].reproducer_path,
            "./fuzz/artifacts/parse/crash-deadbeef"
        );
        assert!(findings[0]
            .summary
            .contains("ERROR: libFuzzer: deadly signal"));
    }

    #[test]
    fn parses_a_timeout() {
        let stderr = concat!(
            "==1234== ERROR: libFuzzer: timeout after 25 seconds\n",
            "SUMMARY: libFuzzer: timeout\n",
            "Test unit written to ./fuzz/artifacts/parse/timeout-abcdef\n",
        );
        let findings = parse_findings(stderr);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::Timeout);
    }

    #[test]
    fn parses_an_oom() {
        let stderr = concat!(
            "==1234== libFuzzer: out-of-memory (used: 2049Mb; limit: 2048Mb)\n",
            "SUMMARY: libFuzzer: out-of-memory\n",
            "Test unit written to ./fuzz/artifacts/parse/oom-cafe\n",
        );
        let findings = parse_findings(stderr);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::OutOfMemory);
        assert_eq!(
            findings[0].reproducer_path,
            "./fuzz/artifacts/parse/oom-cafe"
        );
    }

    #[test]
    fn parses_a_panic_summary() {
        let stderr = concat!(
            "thread '<unnamed>' panicked at 'assertion failed', src/lib.rs:42\n",
            "SUMMARY: libFuzzer: deadly signal\n",
            "Test unit written to ./fuzz/artifacts/parse/crash-1\n",
        );
        let findings = parse_findings(stderr);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].summary.contains("panicked"));
    }

    #[test]
    fn no_summary_means_no_findings() {
        let stderr = concat!(
            "#1\tNEW    cov: 100 ft: 100 corp: 1/1b ...\n",
            "#1000\tpulse  cov: 100 ft: 100 corp: 1/1b ...\n",
            "Done 1000000 in 60s\n",
        );
        assert!(parse_findings(stderr).is_empty());
    }

    #[test]
    fn execution_count_takes_the_max_status_line() {
        let stderr = concat!(
            "#1\tINITED cov: 12 ft: 12 corp: 1/1b\n",
            "#10\tNEW    cov: 13 ft: 13 corp: 2/2b\n",
            "#1024\tpulse  cov: 14 ft: 14 corp: 3/3b\n",
            "#1234567\tDONE   cov: 14 ft: 14 corp: 3/3b\n",
        );
        assert_eq!(parse_executions(stderr), Some(1_234_567));
    }

    #[test]
    fn execution_count_returns_none_when_absent() {
        assert_eq!(parse_executions("no status lines here"), None);
    }

    #[test]
    fn reproducer_path_emitted_before_summary_still_picked_up() {
        let stderr = concat!(
            "Test unit written to ./fuzz/artifacts/parse/crash-before\n",
            "==1234== ERROR: libFuzzer: deadly signal\n",
            "SUMMARY: libFuzzer: deadly signal\n",
        );
        let findings = parse_findings(stderr);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].reproducer_path,
            "./fuzz/artifacts/parse/crash-before"
        );
    }

    #[test]
    fn missing_reproducer_path_falls_back_to_unknown_marker() {
        let stderr = concat!(
            "==1234== ERROR: libFuzzer: deadly signal\n",
            "SUMMARY: libFuzzer: deadly signal\n",
        );
        let findings = parse_findings(stderr);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].reproducer_path.contains("unknown"));
    }

    #[test]
    fn multiple_summaries_produce_multiple_findings() {
        let stderr = concat!(
            "SUMMARY: libFuzzer: deadly signal\n",
            "Test unit written to ./fuzz/artifacts/parse/crash-1\n",
            "SUMMARY: libFuzzer: timeout\n",
            "Test unit written to ./fuzz/artifacts/parse/timeout-1\n",
        );
        let findings = parse_findings(stderr);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].kind, FuzzFindingKind::Crash);
        assert_eq!(findings[1].kind, FuzzFindingKind::Timeout);
    }

    #[test]
    fn allow_list_filters_by_basename() {
        let mut findings = vec![
            FuzzFinding {
                kind: FuzzFindingKind::Crash,
                reproducer_path: "./fuzz/artifacts/parse/crash-deadbeef".into(),
                summary: "x".into(),
            },
            FuzzFinding {
                kind: FuzzFindingKind::Crash,
                reproducer_path: "./fuzz/artifacts/parse/crash-cafebabe".into(),
                summary: "x".into(),
            },
        ];
        apply_allow_list(&mut findings, &["crash-deadbeef".to_string()]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].reproducer_path.ends_with("crash-cafebabe"));
    }

    #[test]
    fn empty_allow_list_is_a_noop() {
        let mut findings = vec![FuzzFinding {
            kind: FuzzFindingKind::Crash,
            reproducer_path: "a".into(),
            summary: "x".into(),
        }];
        apply_allow_list(&mut findings, &[]);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn extract_reproducer_path_handles_quoted_artifact_prefix() {
        let line = "artifact_prefix='./fuzz/artifacts/p/'; Test unit written to ./fuzz/artifacts/p/crash-1";
        assert_eq!(
            extract_reproducer_path(line).as_deref(),
            Some("./fuzz/artifacts/p/crash-1")
        );
    }

    #[test]
    fn summary_kind_recognizes_each_variant() {
        assert_eq!(
            summary_kind("SUMMARY: libFuzzer: deadly signal"),
            Some(FuzzFindingKind::Crash)
        );
        assert_eq!(
            summary_kind("SUMMARY: libFuzzer: timeout"),
            Some(FuzzFindingKind::Timeout)
        );
        assert_eq!(
            summary_kind("SUMMARY: libFuzzer: out-of-memory"),
            Some(FuzzFindingKind::OutOfMemory)
        );
        // Unknown libFuzzer-prefixed summaries fall back to Crash.
        assert_eq!(
            summary_kind("SUMMARY: libFuzzer: weird new mode"),
            Some(FuzzFindingKind::Crash)
        );
        assert_eq!(summary_kind("not a summary line"), None);
    }
}
