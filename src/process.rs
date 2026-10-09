//! Subprocess helper with an optional wall-clock limit.
//!
//! Without a limit this is plain [`Command::output`]. With a limit the
//! child's stdout and stderr are drained on background threads (so a
//! chatty child can never block on a full pipe), the child is polled
//! until it exits or the deadline passes, and on expiry the whole
//! process tree is killed and reaped.

use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How often the child is polled while a deadline is active.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How long to keep collecting output once the child has exited or been
/// killed. A grandchild that inherited the pipes can hold them open after
/// the direct child is gone; this bounds how long we wait for it.
const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Captured result of a subprocess run.
pub(crate) struct Captured {
    /// Exit status, or `None` when the child was killed because the
    /// limit expired.
    pub(crate) status: Option<ExitStatus>,
    /// Everything the child wrote to stdout (partial on timeout).
    pub(crate) stdout: Vec<u8>,
    /// Everything the child wrote to stderr (partial on timeout).
    pub(crate) stderr: Vec<u8>,
}

/// Run `cmd` to completion, or until `limit` elapses.
///
/// Spawn errors are returned as-is so callers can tell "binary not
/// found" apart from other failures.
pub(crate) fn output(cmd: &mut Command, limit: Option<Duration>) -> io::Result<Captured> {
    // A limit so large that the deadline overflows `Instant` is no limit.
    let deadline = match limit.and_then(|d| Instant::now().checked_add(d)) {
        Some(d) => d,
        None => {
            let o = cmd.output()?;
            return Ok(Captured {
                status: Some(o.status),
                stdout: o.stdout,
                stderr: o.stderr,
            });
        }
    };

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        // Lead a new process group so a timeout can kill the whole tree
        // (cargo, the subcommand, test binaries) with one signal.
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = cmd.spawn()?;
    let out = Collector::start(child.stdout.take());
    let err = Collector::start(child.stderr.take());
    let (out, err) = match (out, err) {
        (Ok(o), Ok(e)) => (o, e),
        (Err(e), _) | (_, Err(e)) => {
            kill_tree(&mut child);
            return Err(e);
        }
    };

    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {}
            Err(e) => {
                kill_tree(&mut child);
                return Err(e);
            }
        }
        let now = Instant::now();
        if now >= deadline {
            kill_tree(&mut child);
            break None;
        }
        thread::sleep(POLL_INTERVAL.min(deadline - now));
    };

    let drain_until = Instant::now() + DRAIN_GRACE;
    Ok(Captured {
        status,
        stdout: out.finish(drain_until),
        stderr: err.finish(drain_until),
    })
}

/// Kill `child` and everything it spawned, then reap it. Best effort:
/// failures are ignored because the caller is already on an error path.
fn kill_tree(child: &mut Child) {
    let pid = child.id().to_string();
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/T", "/F", "/PID", &pid])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(unix)]
    {
        // The child leads its own process group, so a negative pid
        // signals the whole group.
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{pid}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(any(windows, unix)))]
    let _ = pid;
    let _ = child.kill();
    let _ = child.wait();
}

/// Drains one pipe on a background thread into a shared buffer.
struct Collector {
    buf: Arc<Mutex<Vec<u8>>>,
    done: mpsc::Receiver<()>,
}

impl Collector {
    fn start<R: Read + Send + 'static>(src: Option<R>) -> io::Result<Self> {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let (tx, done) = mpsc::channel();
        if let Some(mut src) = src {
            let sink = Arc::clone(&buf);
            thread::Builder::new()
                .name("subprocess-drain".into())
                .spawn(move || {
                    let mut chunk = [0u8; 8192];
                    loop {
                        match src.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => match sink.lock() {
                                Ok(mut b) => b.extend_from_slice(&chunk[..n]),
                                Err(p) => p.into_inner().extend_from_slice(&chunk[..n]),
                            },
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(_) => break,
                        }
                    }
                    let _ = tx.send(());
                })?;
        }
        // With no source, `tx` is dropped here and `finish` returns at once.
        Ok(Self { buf, done })
    }

    /// Wait (at most until `until`) for the pipe to close, then take
    /// whatever has been collected.
    fn finish(self, until: Instant) -> Vec<u8> {
        let _ = self
            .done
            .recv_timeout(until.saturating_duration_since(Instant::now()));
        let mut guard = match self.buf.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        std::mem::take(&mut *guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(script: &str) -> Command {
        if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/C", script]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", script]);
            c
        }
    }

    #[test]
    fn no_limit_behaves_like_output() {
        let got = output(&mut shell("echo hello"), None).unwrap();
        assert!(got.status.unwrap().success());
        assert!(String::from_utf8_lossy(&got.stdout).contains("hello"));
    }

    #[test]
    fn generous_limit_captures_both_streams() {
        let got = output(
            &mut shell("echo out && echo err 1>&2"),
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        assert!(got.status.unwrap().success());
        assert!(String::from_utf8_lossy(&got.stdout).contains("out"));
        assert!(String::from_utf8_lossy(&got.stderr).contains("err"));
    }

    #[test]
    fn expired_limit_kills_the_child() {
        let script = if cfg!(windows) {
            "ping -n 30 127.0.0.1 >NUL"
        } else {
            "sleep 30"
        };
        let started = Instant::now();
        let got = output(&mut shell(script), Some(Duration::from_millis(300))).unwrap();
        assert!(got.status.is_none(), "child should have been killed");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "timeout not enforced: took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn huge_limit_does_not_overflow() {
        let got = output(&mut shell("echo ok"), Some(Duration::MAX)).unwrap();
        assert!(got.status.unwrap().success());
    }

    #[test]
    fn spawn_error_is_returned() {
        let err = output(
            &mut Command::new("definitely-not-a-real-binary-dev-fuzz"),
            Some(Duration::from_secs(5)),
        )
        .err()
        .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
