//! Run a fuzz target for a fixed number of executions instead of a
//! wall-clock budget.
//!
//! ```text
//! cargo run --example executions_budget
//! ```

use dev_fuzz::{FuzzBudget, FuzzError, FuzzRun};

fn main() {
    let run = FuzzRun::new("parse_input", "0.1.0").budget(FuzzBudget::executions(100_000));
    let result = match run.execute() {
        Ok(r) => r,
        Err(FuzzError::ToolNotInstalled) | Err(FuzzError::NightlyRequired) => {
            eprintln!("cargo-fuzz / nightly missing; skipping example.");
            return;
        }
        Err(e) => {
            eprintln!("fuzz run failed: {e}");
            return;
        }
    };
    println!(
        "after {} executions: {} findings",
        result.executions,
        result.findings.len()
    );
    for f in &result.findings {
        println!("  [{:?}] {} -> {}", f.kind, f.summary, f.reproducer_path);
    }
}
