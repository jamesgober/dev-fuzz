//! Run a fuzz target for a short time budget and print the report.
//!
//! ```text
//! cargo install cargo-fuzz
//! rustup toolchain install nightly
//! cargo run --example basic
//! ```
//!
//! If `cargo-fuzz` or nightly is missing, the example prints a clear
//! message and exits 0 so `cargo build --examples` keeps working
//! without the toolchain installed.

use std::time::Duration;

use dev_fuzz::{FuzzBudget, FuzzError, FuzzRun};

fn main() {
    let run =
        FuzzRun::new("parse_input", "0.1.0").budget(FuzzBudget::time(Duration::from_secs(10)));
    let result = match run.execute() {
        Ok(r) => r,
        Err(FuzzError::ToolNotInstalled) => {
            eprintln!("cargo-fuzz is not installed; install with `cargo install cargo-fuzz`.");
            return;
        }
        Err(FuzzError::NightlyRequired) => {
            eprintln!("nightly toolchain is required; `rustup toolchain install nightly`.");
            return;
        }
        Err(FuzzError::TargetNotFound(t)) => {
            eprintln!("fuzz target `{t}` was not found in this project; skipping.");
            return;
        }
        Err(e) => {
            eprintln!("fuzz run failed: {e}");
            return;
        }
    };

    println!("Executions: {}", result.executions);
    println!("Findings:   {}", result.findings.len());
    let report = result.into_report();
    println!("{}", report.to_json().expect("serialize report"));
}
