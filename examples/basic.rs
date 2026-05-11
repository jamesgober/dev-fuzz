//! Minimal example: run a fuzz target and emit a report.
//!
//! Run with: `cargo run --example basic`

use dev_fuzz::{FuzzBudget, FuzzRun};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let run =
        FuzzRun::new("parse_input", "0.1.0").budget(FuzzBudget::time(Duration::from_secs(10)));
    let result = run.execute()?;
    println!("Executions: {}", result.executions);
    println!("Findings:   {}", result.findings.len());
    let report = result.into_report();
    println!("{}", report.to_json()?);
    Ok(())
}
