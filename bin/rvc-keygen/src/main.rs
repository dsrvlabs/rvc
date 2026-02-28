mod bls_to_execution;
mod deposit;
mod existing_mnemonic;
mod exit;
mod network;
mod new_mnemonic;
mod password;
mod verify;

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

        /// Passphrase for mnemonic seed derivation
        #[arg(long, default_value = "")]
        mnemonic_passphrase: String,

        /// Use PBKDF2 instead of Scrypt for keystore encryption
        #[arg(long)]
        pbkdf2: bool,

        /// Read keystore password from file instead of prompting
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Derive keys and show output without writing files to disk
        #[arg(long)]
        dry_run: bool,
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

        /// Passphrase for mnemonic seed derivation
        #[arg(long, default_value = "")]
        mnemonic_passphrase: String,

        /// Use PBKDF2 instead of Scrypt for keystore encryption
        #[arg(long)]
        pbkdf2: bool,

        /// Read keystore password from file instead of prompting
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Derive keys and show output without writing files to disk
        #[arg(long)]
        dry_run: bool,
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

        /// BLS withdrawal key index for derivation path m/12381/3600/{index}/0
        #[arg(long, default_value_t = 0)]
        bls_withdrawal_index: u32,
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

        /// Path to the EIP-2335 keystore file
        #[arg(long)]
        keystore: PathBuf,

        /// Read keystore password from file instead of prompting
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::NewMnemonic {
            network,
            output_dir,
            num_validators,
            start_index,
            withdrawal_address,
            mnemonic_passphrase,
            pbkdf2,
            password_file,
            dry_run,
        } => {
            let keystore_password = password::resolve_password(password_file.as_deref())?;
            new_mnemonic::run(
                &network,
                &output_dir,
                num_validators,
                start_index,
                withdrawal_address.as_deref(),
                &mnemonic_passphrase,
                pbkdf2,
                &keystore_password,
                dry_run,
            )
        }
        Commands::ExistingMnemonic {
            network,
            output_dir,
            num_validators,
            start_index,
            withdrawal_address,
            mnemonic_passphrase,
            pbkdf2,
            password_file,
            dry_run,
        } => {
            let keystore_password = password::resolve_password(password_file.as_deref())?;
            existing_mnemonic::run(
                &network,
                &output_dir,
                num_validators,
                start_index,
                withdrawal_address.as_deref(),
                &mnemonic_passphrase,
                pbkdf2,
                &keystore_password,
                dry_run,
            )
        }
        Commands::BlsToExecution {
            network,
            output_dir,
            validator_index,
            execution_address,
            bls_withdrawal_index,
        } => bls_to_execution::run(bls_to_execution::BlsToExecutionArgs {
            network,
            output_dir,
            validator_index,
            execution_address,
            bls_withdrawal_index,
        }),
        Commands::Exit { network, output_dir, validator_index, epoch, keystore, password_file } => {
            exit::run(exit::ExitArgs {
                network,
                output_dir,
                validator_index,
                epoch,
                keystore,
                password_file,
            })
        }
    }
}
