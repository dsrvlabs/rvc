//! rvc - Rust Validator Client
//!
//! Main entry point for the validator client binary: CLI parse, logging init,
//! and one call into [`rvc::bootstrap::run`].

mod cli;
mod commands;
mod logging;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::dispatch(cli::Cli::parse()).await
}

#[cfg(test)]
mod tests {
    /// RF5-10: keep the binary entry point under the line-count budget.
    #[test]
    fn test_main_rs_under_600_lines() {
        let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let lines = src.lines().count();
        assert!(
            lines < 600,
            "bin/rvc/src/main.rs must stay under 600 lines after RF5-10 (found {lines})"
        );
    }
}
