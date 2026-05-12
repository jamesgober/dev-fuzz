//! Demonstrate `FuzzProducer` — the `dev_report::Producer` adapter.
//!
//! Construction is always safe and cheap. The actual subprocess
//! invocation is gated behind the `DEV_FUZZ_EXAMPLE_RUN` env var so
//! CI doesn't pay for a real fuzz run on every example build.
//!
//! ```text
//! cargo run --example producer
//! DEV_FUZZ_EXAMPLE_RUN=1 cargo run --example producer
//! ```

use std::time::Duration;

use dev_fuzz::{FuzzBudget, FuzzProducer, FuzzRun};
use dev_report::Producer;

fn main() {
    let producer = FuzzProducer::new(
        FuzzRun::new("parse_input", "0.1.0").budget(FuzzBudget::time(Duration::from_secs(10))),
    );
    println!("Constructed FuzzProducer for 'parse_input' v0.1.0.");

    if std::env::var("DEV_FUZZ_EXAMPLE_RUN").is_ok() {
        let report = producer.produce();
        println!("{}", report.to_json().expect("serialize report"));
    } else {
        println!("Set DEV_FUZZ_EXAMPLE_RUN=1 to spawn `cargo +nightly fuzz run parse_input`");
        println!("with a 10s budget and print the resulting JSON report.");
    }
}
