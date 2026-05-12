//! Configure per-iteration timeout, RSS limit, and sanitizer.
//!
//! ```text
//! cargo run --example with_limits
//! ```

use std::time::Duration;

use dev_fuzz::{FuzzBudget, FuzzError, FuzzRun, Sanitizer};

fn main() {
    let run = FuzzRun::new("parse_input", "0.1.0")
        .budget(FuzzBudget::time(Duration::from_secs(30)))
        .sanitizer(Sanitizer::Address)
        .timeout_per_iter(Duration::from_secs(5))
        .rss_limit_mb(2048)
        .allow("crash-known-false-positive");

    match run.execute() {
        Ok(r) => println!("done: {} findings", r.findings.len()),
        Err(FuzzError::ToolNotInstalled) | Err(FuzzError::NightlyRequired) => {
            eprintln!("cargo-fuzz / nightly missing; skipping example.");
        }
        Err(e) => eprintln!("fuzz run failed: {e}"),
    }
}
