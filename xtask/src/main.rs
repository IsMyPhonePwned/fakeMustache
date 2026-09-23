use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run unit/property tests for the workspace
    Test,
    /// Placeholder for §3 contract tests against sibling extractors
    Contract,
    /// Print coverage / corpus notes
    Coverage,
}

fn main() {
    let args = Args::parse();
    match args.cmd {
        Cmd::Test => {
            let status = std::process::Command::new("cargo")
                .args(["test", "--workspace", "--exclude", "fm-wasm"])
                .status()
                .expect("cargo");
            std::process::exit(status.code().unwrap_or(1));
        }
        Cmd::Contract => {
            println!(
                "Contract tests require path deps on ../bugreport-extractor-library and ../sysdiagnose-extractor-library."
            );
            println!(
                "Wire in CI: extract A → anonymize → extract A' → assert apply(M, J) == J' modulo declared divergences."
            );
            println!("SIGMA_FIELDS.md is the authoritative preservation list.");
        }
        Cmd::Coverage => {
            println!("Public corpus: testdata/canary (synthetic).");
            println!("sysdiagnose-testdata: https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata");
            println!("Real-device corpora: reference by hash only; private CI.");
        }
    }
}
