#[allow(dead_code)]
mod deposit;
#[allow(dead_code)]
mod network;
#[allow(dead_code)]
mod password;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rvc-keygen", about = "Ethereum validator key generation tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new mnemonic and derive validator keys
    NewMnemonic {
        /// Network name (mainnet, hoodi)
        #[arg(long, default_value = "mainnet")]
        network: String,

        /// Output directory for keystores and deposit data
        #[arg(long, default_value = "./validator_keys")]
        output_dir: PathBuf,

        /// Number of validators to generate
        #[arg(long, default_value_t = 1)]
        num_validators: u32,

        /// Starting index for key derivation
        #[arg(long, default_value_t = 0)]
        start_index: u32,

        /// Execution address for 0x01 withdrawal credentials
        #[arg(long)]
        withdrawal_address: Option<String>,
    },

    /// Regenerate keys from an existing mnemonic
    ExistingMnemonic {
        /// Network name (mainnet, hoodi)
        #[arg(long, default_value = "mainnet")]
        network: String,

        /// Output directory for keystores and deposit data
        #[arg(long, default_value = "./validator_keys")]
        output_dir: PathBuf,

        /// Number of validators to generate
        #[arg(long, default_value_t = 1)]
        num_validators: u32,

        /// Starting index for key derivation
        #[arg(long, default_value_t = 0)]
        start_index: u32,

        /// Execution address for 0x01 withdrawal credentials
        #[arg(long)]
        withdrawal_address: Option<String>,
    },

    /// Generate a BLS-to-execution-change message
    BlsToExecution {
        /// Network name (mainnet, hoodi)
        #[arg(long, default_value = "mainnet")]
        network: String,

        /// Output directory
        #[arg(long, default_value = "./bls_to_execution_changes")]
        output_dir: PathBuf,

        /// Validator index on the beacon chain
        #[arg(long)]
        validator_index: u64,

        /// Execution address to set as withdrawal target
        #[arg(long)]
        execution_address: String,
    },

    /// Generate a signed voluntary exit message
    Exit {
        /// Network name (mainnet, hoodi)
        #[arg(long, default_value = "mainnet")]
        network: String,

        /// Output directory
        #[arg(long, default_value = "./signed_exits")]
        output_dir: PathBuf,

        /// Validator index on the beacon chain
        #[arg(long)]
        validator_index: u64,

        /// Epoch at which to exit
        #[arg(long)]
        epoch: u64,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::NewMnemonic { .. } => {
            todo!("new-mnemonic subcommand not yet implemented")
        }
        Commands::ExistingMnemonic { .. } => {
            todo!("existing-mnemonic subcommand not yet implemented")
        }
        Commands::BlsToExecution { .. } => {
            todo!("bls-to-execution subcommand not yet implemented")
        }
        Commands::Exit { .. } => {
            todo!("exit subcommand not yet implemented")
        }
    }
}
