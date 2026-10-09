//! `cargo fuzz` subprocess invocation + libFuzzer stderr parser.
//!
//! libFuzzer writes its output to stderr. Each finding ends with a
//! `SUMMARY:` line and writes one artifact (the reproducer). The order
//! depends on the kind of finding (see `FuzzerLoop.cpp` in LLVM):
//!
//! ```text
//! # Crash (Rust panic or signal): artifact AFTER the summary.
//! thread '<unnamed>' panicked at fuzz_targets/parse.rs:5:9:
//! index out of bounds: the len is 0 but the index is 0
//! ==1234== ERROR: libFuzzer: deadly signal
//!     #0 0x55d1c2 in __sanitizer_print_stack_trace
//! SUMMARY: libFuzzer: deadly signal
//! MS: 1 ChangeByte-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
//! artifact_prefix='/w/fuzz/artifacts/parse/'; Test unit written to /w/fuzz/artifacts/parse/crash-<sha1>
//!
//! # Timeout: artifact BEFORE the ERROR line and the stack trace.
//! ALARM: working on the last Unit for 2 seconds
//! artifact_prefix='...'; Test unit written to .../timeout-<sha1>
//! ==1234== ERROR: libFuzzer: timeout after 2 seconds
//! SUMMARY: libFuzzer: timeout
//!
//! # Out of memory: artifact BEFORE the summary.
//! ==1234== ERROR: libFuzzer: out-of-memory (used: 2085Mb; exceeds: 2048Mb)
//! artifact_prefix='...'; Test unit written to .../oom-<sha1>
//! SUMMARY: libFuzzer: out-of-memory
//!
//! # Sanitizer report (AddressSanitizer, LeakSanitizer, ...).
//! ==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
//! SUMMARY: AddressSanitizer: heap-buffer-overflow ... in parse
//! artifact_prefix='...'; Test unit written to .../crash-<sha1>   (leak-<sha1> for leaks)
//! ```
//!
//! Each `SUMMARY:` line anchors one finding. Its reproducer is the
//! `Test unit written to` line between the neighboring summaries,
//! preferring an artifact whose name prefix (`crash-`, `leak-`,
//! `timeout-`, `oom-`) matches the kind. Artifacts with a known prefix
//! but no summary (truncated output) still become findings.
//!
//! Execution counts come from libFuzzer's status lines (`#1234\tNEW ...`,
//! `#1234: cov: ...` in fork mode), `Done 1234 runs in 60 second(s)` and
//! `stat::number_of_executed_units: 1234`; the highest value wins.

use std::process::{Command, ExitStatus};
use std::time::Duration;

use crate::{process, FuzzError, FuzzFinding, FuzzFindingKind, FuzzResult, FuzzRun};

pub(crate) fn run(cfg: &FuzzRun) -> Result<FuzzResult, FuzzError> {
    if let Some(dir) = cfg.workdir_path() {
        if !dir.is_dir() {
            return Err(FuzzError::SubprocessFailed(format!(
                "working directory does not exist: {}",
                dir.display()
            )));
        }
    }
    detect_cargo_fuzz(cfg)?;
    detect_nightly(cfg)?;
    ensure_target_exists(cfg)?;

    let mut cmd = build_command(cfg);
    let output = process::output(&mut cmd, cfg.run_timeout_value())
        .map_err(|e| FuzzError::SubprocessFailed(format!("could not run cargo fuzz: {e}")))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    interpret(cfg, output.status, &stdout, &stderr)
}

/// Turn the captured run into a result. `status` is `None` when the run
/// was killed because [`FuzzRun::run_timeout`] expired.
fn interpret(
    cfg: &FuzzRun,
    status: Option<ExitStatus>,
    stdout: &str,
    stderr: &str,
) -> Result<FuzzResult, FuzzError> {
    let mut findings = parse_findings(stderr);
    // Decide success or failure on the unfiltered findings: a run that
    // stopped on an allow-listed crash is not a harness failure.
    let found_any = !findings.is_empty();
    apply_allow_list(&mut findings, cfg.allow_list_view());
    let executions = parse_executions(stderr)
        .max(parse_executions(stdout))
        .unwrap_or(0);

    if !found_any {
        match status {
            None => {
                return Err(FuzzError::SubprocessFailed(format!(
                    "timed out after {:?}; process tree killed\n{}",
                    cfg.run_timeout_value().unwrap_or(Duration::ZERO),
                    tail(stderr, 60)
                )))
            }
            Some(status) if !status.success() => {
                // Non-zero exit without a recognizable finding: surface
                // the end of stderr (build errors, harness errors) rather
                // than a silent empty result.
                return Err(FuzzError::SubprocessFailed(format!(
                    "exited with {status}\n{}",
                    tail(stderr, 60)
                )));
            }
            Some(_) => {}
        }
    }

    Ok(FuzzResult {
        target: cfg.target_name().to_string(),
        version: cfg.subject_version().to_string(),
        executions,
        findings,
    })
}

/// Last `n` lines of `s`.
fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

fn probe_command(cfg: &FuzzRun, args: &[&str]) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.args(args);
    if let Some(dir) = cfg.workdir_path() {
        cmd.current_dir(dir);
    }
    cmd
}

fn probe(cfg: &FuzzRun, args: &[&str]) -> std::io::Result<std::process::Output> {
    probe_command(cfg, args).output()
}

/// `true` when cargo's stderr says the subcommand does not exist.
/// Current cargo prints "no such command", older releases printed
/// "no such subcommand".
fn is_missing_subcommand(stderr: &str) -> bool {
    stderr.contains("no such command") || stderr.contains("no such subcommand")
}

fn detect_cargo_fuzz(cfg: &FuzzRun) -> Result<(), FuzzError> {
    match probe(cfg, &["fuzz", "--version"]) {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if is_missing_subcommand(&stderr) {
                Err(FuzzError::ToolNotInstalled)
            } else {
                Err(FuzzError::SubprocessFailed(format!(
                    "`cargo fuzz --version` exited with {}\n{}",
                    o.status,
                    stderr.trim_end()
                )))
            }
        }
        // `cargo` itself could not be started (not on PATH).
        Err(_) => Err(FuzzError::ToolNotInstalled),
    }
}

/// Probe exactly what the run uses: `cargo +nightly`. A dated nightly
/// (`nightly-2026-01-01`) alone does not satisfy `+nightly`, and without
/// rustup the `+toolchain` syntax is not available at all; both cases
/// fail this probe.
///
/// The probe must not install anything: `RUSTUP_AUTO_INSTALL=0` stops
/// rustup releases that would otherwise download a missing toolchain.
fn detect_nightly(cfg: &FuzzRun) -> Result<(), FuzzError> {
    let mut cmd = probe_command(cfg, &["+nightly", "--version"]);
    cmd.env("RUSTUP_AUTO_INSTALL", "0");
    match cmd.output() {
        Ok(o) if o.status.success() => Ok(()),
        _ => Err(FuzzError::NightlyRequired),
    }
}

fn ensure_target_exists(cfg: &FuzzRun) -> Result<(), FuzzError> {
    let output = match probe(cfg, &["fuzz", "list"]) {
        Ok(o) => o,
        Err(_) => return Ok(()), // can't list; let the run itself surface the error
    };
    if !output.status.success() {
        // `cargo fuzz list` failing is itself usually a "no fuzz/ dir"
        // condition. Let `run` surface a more informative error.
        return Ok(());
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    if target_listed(&listing, cfg.target_name()) {
        Ok(())
    } else {
        Err(FuzzError::TargetNotFound(cfg.target_name().to_string()))
    }
}

fn target_listed(listing: &str, target: &str) -> bool {
    listing
        .lines()
        .map(str::trim)
        .any(|l| !l.is_empty() && l == target)
}

fn build_command(cfg: &FuzzRun) -> Command {
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
    cmd
}

/// Final path component, splitting on both `/` and `\` so Windows paths
/// work on every host.
fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn apply_allow_list(findings: &mut Vec<FuzzFinding>, allow_list: &[String]) {
    if allow_list.is_empty() {
        return;
    }
    findings.retain(|f| {
        let name = basename(&f.reproducer_path);
        !allow_list.iter().any(|n| n == name)
    });
}

// ---------------------------------------------------------------------------
// Stderr parser
// ---------------------------------------------------------------------------

/// Placeholder used when no `Test unit written to` line belongs to a
/// finding. Starts with `<` so it can never be a real artifact path.
fn unknown_reproducer(kind: FuzzFindingKind) -> String {
    format!("<unknown reproducer for {}>", kind.label())
}

pub(crate) fn parse_findings(stderr: &str) -> Vec<FuzzFinding> {
    let lines: Vec<&str> = stderr.lines().collect();
    let summaries: Vec<(usize, FuzzFindingKind)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| summary_kind(l).map(|k| (i, k)))
        .collect();
    let artifacts: Vec<(usize, String)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| extract_reproducer_path(l.trim()).map(|p| (i, p)))
        .collect();
    let mut used = vec![false; artifacts.len()];
    // (anchor line, finding) so the output follows stderr order.
    let mut found: Vec<(usize, FuzzFinding)> = Vec::new();

    for (n, &(at, kind)) in summaries.iter().enumerate() {
        let lo = if n == 0 { 0 } else { summaries[n - 1].0 + 1 };
        let hi = summaries.get(n + 1).map_or(lines.len(), |s| s.0);
        let free = |j: usize, line: usize| !used[j] && line >= lo && line < hi;
        let pick = artifacts
            .iter()
            .enumerate()
            .filter(|(j, (line, p))| free(*j, *line) && artifact_kind(p) == Some(kind))
            .min_by_key(|(_, (line, _))| line.abs_diff(at))
            .or_else(|| {
                // Crash artifacts follow their summary...
                artifacts
                    .iter()
                    .enumerate()
                    .find(|(j, (line, _))| free(*j, *line) && *line > at)
            })
            .or_else(|| {
                // ...timeout and OOM artifacts precede it.
                artifacts
                    .iter()
                    .enumerate()
                    .rev()
                    .find(|(j, (line, _))| free(*j, *line) && *line < at)
            })
            .map(|(j, _)| j);
        let reproducer_path = match pick {
            Some(j) => {
                used[j] = true;
                artifacts[j].1.clone()
            }
            None => unknown_reproducer(kind),
        };
        found.push((
            at,
            FuzzFinding {
                kind,
                reproducer_path,
                summary: describe(&lines, lo, at),
            },
        ));
    }

    // Artifacts that no summary claimed (for example output cut off
    // before the SUMMARY line) still identify a finding by their prefix.
    for (j, (line, path)) in artifacts.iter().enumerate() {
        if used[j] {
            continue;
        }
        let Some(kind) = artifact_kind(path) else {
            continue;
        };
        let lo = summaries
            .iter()
            .rev()
            .find(|(s, _)| s < line)
            .map_or(0, |(s, _)| s + 1);
        found.push((
            *line,
            FuzzFinding {
                kind,
                reproducer_path: path.clone(),
                summary: describe(&lines, lo, *line),
            },
        ));
    }

    found.sort_by_key(|(at, _)| *at);
    let mut out: Vec<FuzzFinding> = Vec::with_capacity(found.len());
    for (_, f) in found {
        // One artifact is one finding; repeated sanitizer reports without
        // an artifact (e.g. ThreadSanitizer with halt_on_error=0) collapse
        // to one finding per distinct summary.
        let dup = out.iter().any(|o| {
            o.reproducer_path == f.reproducer_path
                && (!f.reproducer_path.starts_with('<') || o.summary == f.summary)
        });
        if !dup {
            out.push(f);
        }
    }
    out
}

/// Kind of finding a `SUMMARY:` line reports, or `None` for any other
/// line.
fn summary_kind(line: &str) -> Option<FuzzFindingKind> {
    let rest = line.trim().strip_prefix("SUMMARY:")?.trim_start();
    if let Some(r) = rest.strip_prefix("libFuzzer:") {
        let r = r.trim();
        return Some(if r.starts_with("timeout") {
            FuzzFindingKind::Timeout
        } else if r.starts_with("out-of-memory") {
            FuzzFindingKind::OutOfMemory
        } else {
            // Everything else from libFuzzer (deadly signal, fuzz target
            // exited, overwrites const input, ...) is a crash.
            FuzzFindingKind::Crash
        });
    }
    // `SUMMARY: AddressSanitizer: ...`, `SUMMARY: MemorySanitizer: ...`, ...
    let (tool, what) = rest.split_once(':')?;
    if !tool.ends_with("Sanitizer") || tool.contains(char::is_whitespace) {
        return None;
    }
    let what = what.trim_start();
    if what.starts_with("out-of-memory") || what.starts_with("out of memory") {
        Some(FuzzFindingKind::OutOfMemory)
    } else {
        Some(FuzzFindingKind::Crash)
    }
}

/// Kind implied by a libFuzzer artifact name prefix.
fn artifact_kind(path: &str) -> Option<FuzzFindingKind> {
    let name = basename(path);
    if name.starts_with("crash-") || name.starts_with("leak-") {
        Some(FuzzFindingKind::Crash)
    } else if name.starts_with("timeout-") {
        Some(FuzzFindingKind::Timeout)
    } else if name.starts_with("oom-") {
        Some(FuzzFindingKind::OutOfMemory)
    } else {
        None
    }
}

/// Best one-line description of the finding anchored at `at`, looking
/// back no further than `lo`: a Rust panic message first, then a
/// sanitizer / libFuzzer `ERROR:` line, then the anchor line itself.
fn describe(lines: &[&str], lo: usize, at: usize) -> String {
    let window = lines.get(lo..at).unwrap_or(&[]);
    for (k, line) in window.iter().enumerate().rev() {
        let t = line.trim();
        if t.starts_with("thread '") && t.contains("panicked at") {
            // Since Rust 1.73 the message is on the next line.
            if t.ends_with(':') {
                if let Some(msg) = window
                    .get(k + 1)
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                {
                    return format!("{t} {msg}");
                }
            }
            return t.to_string();
        }
    }
    for line in window.iter().rev() {
        let t = line.trim();
        if (t.starts_with("==") && t.contains("ERROR: ")) || t.starts_with("ERROR:") {
            return t.to_string();
        }
    }
    lines
        .get(at)
        .map_or_else(String::new, |l| l.trim().to_string())
}

fn extract_reproducer_path(line: &str) -> Option<String> {
    let marker = "Test unit written to ";
    let idx = line.find(marker)?;
    let after = &line[idx + marker.len()..];
    // Path runs until end of line; libFuzzer doesn't quote it, so paths
    // with spaces are kept whole.
    let path = after.trim();
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

pub(crate) fn parse_executions(output: &str) -> Option<u64> {
    output.lines().filter_map(executions_in_line).max()
}

/// Execution count reported by one libFuzzer output line, if any.
fn executions_in_line(line: &str) -> Option<u64> {
    let line = line.trim_end();
    // Status lines start in column 0: `#1234\tNEW    cov: ...` or, in
    // fork mode, `#1234: cov: ...`. Sanitizer stack frames (`    #3 0x...`)
    // are indented and followed by an address, so they never match.
    if let Some(rest) = line.strip_prefix('#') {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let after = &rest[digits..];
        let is_status = after.starts_with(':')
            || (after.starts_with(char::is_whitespace)
                && after
                    .trim_start()
                    .starts_with(|c: char| c.is_ascii_alphabetic()));
        return if is_status {
            rest[..digits].parse().ok()
        } else {
            None
        };
    }
    // `Done 1234 runs in 60 second(s)`
    if let Some(rest) = line.strip_prefix("Done ") {
        let (n, tail) = rest.split_once(' ')?;
        return if tail.starts_with("runs") {
            n.parse().ok()
        } else {
            None
        };
    }
    // `stat::number_of_executed_units: 1234` (-print_final_stats=1)
    line.strip_prefix("stat::number_of_executed_units:")
        .and_then(|n| n.trim().parse().ok())
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

    // -----------------------------------------------------------------
    // Fixtures laid out the way libFuzzer (FuzzerLoop.cpp) and
    // cargo-fuzz print them. cargo-fuzz is not installed on the machine
    // these were written on, so they follow the documented order rather
    // than a capture.
    // -----------------------------------------------------------------

    /// `    #N 0x... in frame_N` lines, the way sanitizers print stacks.
    fn stack(frames: usize) -> String {
        (0..frames)
            .map(|n| format!("    #{n} 0x55f1c0bd{n:04x} in frame_{n} /src/x.rs:{n}:1\n"))
            .collect()
    }

    fn rust_panic_crash() -> String {
        format!(
            concat!(
                "INFO: Running with entropic power schedule (0xFF, 100).\n",
                "INFO: Seed: 1608565063\n",
                "INFO:        0 files found in /home/u/my proj/fuzz/corpus/parse\n",
                "#2\tINITED cov: 5 ft: 5 corp: 1/1b exec/s: 0 rss: 31Mb\n",
                "#3\tNEW    cov: 6 ft: 6 corp: 2/2b lim: 4 exec/s: 0 rss: 31Mb L: 1/1 MS: 1 ChangeBit-\n",
                "#1024\tpulse  cov: 9 ft: 12 corp: 5/14b lim: 11 exec/s: 0 rss: 32Mb\n",
                "thread '<unnamed>' panicked at fuzz_targets/parse.rs:7:9:\n",
                "index out of bounds: the len is 3 but the index is 3\n",
                "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n",
                "==4242== ERROR: libFuzzer: deadly signal\n",
                "{}",
                "NOTE: libFuzzer has rudimentary signal handlers.\n",
                "      Combine libFuzzer with AddressSanitizer or similar for better crash reports.\n",
                "SUMMARY: libFuzzer: deadly signal\n",
                "MS: 2 InsertByte-ChangeBit-; base unit: 3f786850e387550fdab836ed7e6dc881de23001b\n",
                "0x61,0x62,0x63,\n",
                "abc\n",
                "artifact_prefix='/home/u/my proj/fuzz/artifacts/parse/'; Test unit written to /home/u/my proj/fuzz/artifacts/parse/crash-a9993e364706816aba3e25717850c26c9cd0d89d\n",
                "Base64: YWJj\n",
                "\n",
                "Failing input:\n",
                "\n",
                "\tfuzz/artifacts/parse/crash-a9993e364706816aba3e25717850c26c9cd0d89d\n",
                "\n",
                "Error: Fuzz target exited with exit status: 77\n",
            ),
            stack(36)
        )
    }

    #[test]
    fn rust_panic_with_deep_stack_trace() {
        let stderr = rust_panic_crash();
        let findings = parse_findings(&stderr);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.kind, FuzzFindingKind::Crash);
        // Space in the path is preserved.
        assert_eq!(
            f.reproducer_path,
            "/home/u/my proj/fuzz/artifacts/parse/crash-a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        // The panic message beats the generic "deadly signal" line.
        assert_eq!(
            f.summary,
            "thread '<unnamed>' panicked at fuzz_targets/parse.rs:7:9: index out of bounds: the len is 3 but the index is 3"
        );
        // Stack frame numbers (#0..#35) are not execution counts.
        assert_eq!(parse_executions(&stderr), Some(1024));
    }

    #[test]
    fn timeout_artifact_before_deep_stack_with_crlf_and_windows_path() {
        let stderr = format!(
            concat!(
                "#2\tINITED cov: 4 ft: 4 corp: 1/1b exec/s: 0 rss: 30Mb\n",
                "#8\tNEW    cov: 5 ft: 5 corp: 2/3b lim: 4 exec/s: 0 rss: 30Mb L: 2/2 MS: 1 InsertByte-\n",
                "ALARM: working on the last Unit for 2 seconds\n",
                "       and the timeout value is 1 (use -timeout=N to change)\n",
                "MS: 1 ChangeByte-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc\n",
                "0x6c,0x6f,\n",
                "lo\n",
                "artifact_prefix='C:\\w s\\fuzz\\artifacts\\parse\\'; Test unit written to C:\\w s\\fuzz\\artifacts\\parse\\timeout-1f2d3c4b\n",
                "Base64: bG8=\n",
                "==7== ERROR: libFuzzer: timeout after 2 seconds\n",
                "{}",
                "SUMMARY: libFuzzer: timeout\n",
            ),
            stack(40)
        )
        .replace('\n', "\r\n");
        let findings = parse_findings(&stderr);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.kind, FuzzFindingKind::Timeout);
        assert_eq!(
            f.reproducer_path,
            r"C:\w s\fuzz\artifacts\parse\timeout-1f2d3c4b"
        );
        assert_eq!(f.summary, "==7== ERROR: libFuzzer: timeout after 2 seconds");
        assert_eq!(parse_executions(&stderr), Some(8));
    }

    #[test]
    fn oom_with_final_stats() {
        let stderr = concat!(
            "#4096\tpulse  cov: 20 ft: 30 corp: 9/99b lim: 43 exec/s: 2048 rss: 1500Mb\n",
            "==31== ERROR: libFuzzer: out-of-memory (used: 2085Mb; exceeds: 2048Mb)\n",
            "   To change the out-of-memory limit use -rss_limit_mb=<N>\n",
            "\n",
            "Live Heap Allocations: 2147483648 bytes in 1 chunks; quarantined: 0 bytes in 0 chunks\n",
            "MS: 1 CopyPart-; base unit: 0b6a4f3b2c1d\n",
            "artifact_prefix='./'; Test unit written to ./oom-99ab\n",
            "SUMMARY: libFuzzer: out-of-memory\n",
            "stat::number_of_executed_units: 5321\n",
            "stat::average_exec_per_sec:     887\n",
        );
        let findings = parse_findings(stderr);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::OutOfMemory);
        assert_eq!(findings[0].reproducer_path, "./oom-99ab");
        assert!(findings[0].summary.contains("out-of-memory (used: 2085Mb"));
        assert_eq!(parse_executions(stderr), Some(5321));
    }

    #[test]
    fn address_sanitizer_report_is_a_crash() {
        let stderr = format!(
            concat!(
                "=================================================================\n",
                "==99==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011 at pc 0x55 bp 0x7ffd sp 0x7ffc\n",
                "READ of size 1 at 0x602000000011 thread T0\n",
                "{}",
                "SUMMARY: AddressSanitizer: heap-buffer-overflow src/lib.rs:12:5 in parse::decode\n",
                "Shadow bytes around the buggy address:\n",
                "==99==ABORTING\n",
                "MS: 1 EraseBytes-; base unit: 1d2a\n",
                "0x1,\n",
                "\\x01\n",
                "artifact_prefix='/w/fuzz/artifacts/parse/'; Test unit written to /w/fuzz/artifacts/parse/crash-5ba93c9d\n",
                "Base64: AQ==\n",
            ),
            stack(12)
        );
        let findings = parse_findings(&stderr);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::Crash);
        assert_eq!(
            findings[0].reproducer_path,
            "/w/fuzz/artifacts/parse/crash-5ba93c9d"
        );
        assert!(findings[0]
            .summary
            .starts_with("==99==ERROR: AddressSanitizer: heap-buffer-overflow"));
    }

    #[test]
    fn leak_report_is_a_crash_with_leak_artifact() {
        let stderr = concat!(
            "==12==ERROR: LeakSanitizer: detected memory leaks\n",
            "\n",
            "Direct leak of 16 byte(s) in 1 object(s) allocated from:\n",
            "    #0 0x4a1b in malloc\n",
            "SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).\n",
            "\n",
            "INFO: to ignore leaks on libFuzzer side use -detect_leaks=0.\n",
            "\n",
            "MS: 0 ; base unit: 0000000000000000000000000000000000000000\n",
            "artifact_prefix='./'; Test unit written to ./leak-da39a3ee\n",
        );
        let findings = parse_findings(stderr);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::Crash);
        assert_eq!(findings[0].reproducer_path, "./leak-da39a3ee");
        assert!(findings[0].summary.contains("LeakSanitizer"));
    }

    #[test]
    fn artifact_without_summary_still_counts() {
        // Output cut off after the artifact line.
        let stderr = concat!(
            "#100\tNEW    cov: 3 ft: 3 corp: 2/2b\n",
            "==5== ERROR: libFuzzer: deadly signal\n",
            "artifact_prefix='./'; Test unit written to ./crash-123\n",
            "artifact_prefix='./'; Test unit written to ./slow-unit-456\n",
        );
        let findings = parse_findings(stderr);
        assert_eq!(findings.len(), 1, "slow-unit artifacts are not findings");
        assert_eq!(findings[0].kind, FuzzFindingKind::Crash);
        assert_eq!(findings[0].reproducer_path, "./crash-123");
        assert_eq!(findings[0].summary, "==5== ERROR: libFuzzer: deadly signal");
    }

    #[test]
    fn repeated_sanitizer_reports_without_artifact_are_deduplicated() {
        let race = concat!(
            "WARNING: ThreadSanitizer: data race (pid=9)\n",
            "SUMMARY: ThreadSanitizer: data race src/lib.rs:5 in f\n",
        );
        let other = "SUMMARY: ThreadSanitizer: data race src/lib.rs:9 in g\n";
        let stderr = format!("{race}{race}{other}");
        let findings = parse_findings(&stderr);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.kind == FuzzFindingKind::Crash));
        assert!(findings
            .iter()
            .all(|f| f.reproducer_path == "<unknown reproducer for crash>"));
    }

    #[test]
    fn summary_kind_recognizes_sanitizers() {
        assert_eq!(
            summary_kind("SUMMARY: MemorySanitizer: use-of-uninitialized-value src/a.rs:3"),
            Some(FuzzFindingKind::Crash)
        );
        assert_eq!(
            summary_kind("SUMMARY: AddressSanitizer: out-of-memory: allocator is trying to allocate 0x100000000 bytes"),
            Some(FuzzFindingKind::OutOfMemory)
        );
        assert_eq!(summary_kind("SUMMARY: 3 tests failed: x"), None);
        assert_eq!(summary_kind("SUMMARY:"), None);
    }

    #[test]
    fn executions_from_done_and_fork_lines() {
        assert_eq!(
            parse_executions("Done 65536 runs in 3 second(s)\n"),
            Some(65536)
        );
        assert_eq!(
            parse_executions(
                "#47965: cov: 210 ft: 450 corp: 50 exec/s 15978 oom/timeout/crash: 0/0/0 time: 3s job: 1\n"
            ),
            Some(47965)
        );
        // Not status lines.
        assert_eq!(
            parse_executions("#12 0x55f1 in foo\n    #900 in bar\n#\n"),
            None
        );
        assert_eq!(parse_executions("Done 5 things\n"), None);
        // Overflowing numbers are skipped, not a panic.
        assert_eq!(
            parse_executions("#99999999999999999999999\tNEW cov: 1\n#7\tNEW cov: 1\n"),
            Some(7)
        );
    }

    #[test]
    fn allow_list_matches_windows_basename() {
        let mut findings = vec![FuzzFinding {
            kind: FuzzFindingKind::Crash,
            reproducer_path: r"C:\w\fuzz\artifacts\parse\crash-deadbeef".into(),
            summary: "x".into(),
        }];
        apply_allow_list(&mut findings, &["crash-deadbeef".to_string()]);
        assert!(findings.is_empty());
    }

    #[test]
    fn target_listing_handles_crlf() {
        assert!(target_listed("parse\r\nfuzz_decode\r\n", "fuzz_decode"));
        assert!(!target_listed("parse\r\n", "pars"));
    }

    #[cfg(any(unix, windows))]
    fn status(code: i32) -> ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(code << 8)
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(code as u32)
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn interpret_maps_exit_and_findings() {
        let cfg = FuzzRun::new("parse", "0.1.0");
        // Clean run.
        let ok = interpret(&cfg, Some(status(0)), "", "Done 10 runs in 1 second(s)\n").unwrap();
        assert_eq!(ok.executions, 10);
        assert!(ok.findings.is_empty());
        // Crash: non-zero exit with a finding is a result, not an error.
        let crash = interpret(&cfg, Some(status(1)), "", &rust_panic_crash()).unwrap();
        assert_eq!(crash.findings.len(), 1);
        assert_eq!(crash.executions, 1024);
        // Non-zero exit without a finding (build error) is an error.
        let err = interpret(
            &cfg,
            Some(status(101)),
            "",
            "error[E0425]: cannot find value `x`\nerror: could not compile `parse-fuzz`\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("could not compile"));
        // Killed by run_timeout with nothing found.
        let cfg_t = cfg.clone().run_timeout(Duration::from_secs(5));
        let err = interpret(&cfg_t, None, "", "#2\tINITED cov: 1\n").unwrap_err();
        assert!(err.to_string().contains("timed out after 5s"));
        // Killed by run_timeout after a crash was written: keep the finding.
        let late = interpret(&cfg_t, None, "", &rust_panic_crash()).unwrap();
        assert_eq!(late.findings.len(), 1);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn allow_listed_crash_is_not_a_harness_failure() {
        let cfg =
            FuzzRun::new("parse", "0.1.0").allow("crash-a9993e364706816aba3e25717850c26c9cd0d89d");
        let r = interpret(&cfg, Some(status(1)), "", &rust_panic_crash()).unwrap();
        assert!(r.findings.is_empty());
        assert_eq!(r.executions, 1024);
    }

    #[test]
    fn command_line_is_cargo_fuzz_run_with_libfuzzer_flags() {
        let cfg = FuzzRun::new("parse", "0.1.0")
            .budget(crate::FuzzBudget::executions(500))
            .sanitizer(crate::Sanitizer::None)
            .timeout_per_iter(Duration::from_millis(1500))
            .rss_limit_mb(512);
        let cmd = build_command(&cfg);
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "+nightly",
                "fuzz",
                "run",
                "--sanitizer",
                "none",
                "parse",
                "--",
                "-runs=500",
                "-timeout=1",
                "-rss_limit_mb=512"
            ]
        );
    }

    #[test]
    fn missing_subcommand_detection_matches_cargo_wording() {
        // Captured from cargo 1.9x without cargo-fuzz installed.
        assert!(is_missing_subcommand(
            "error: no such command: `fuzz`\n\nhelp: a command with a similar name exists: `fix`\n"
        ));
        assert!(is_missing_subcommand(
            "error: no such subcommand: `fuzz`\r\n"
        ));
        assert!(!is_missing_subcommand("error: could not find `Cargo.toml`"));
    }
}
