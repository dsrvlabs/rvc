#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYGEN_BIN="$PROJECT_ROOT/target/release/rvc-keygen"

# Sentinel for "not provided via CLI flag"
_UNSET="__UNSET__"

NETWORK="$_UNSET"
NUM_VALIDATORS="$_UNSET"
WITHDRAWAL_ADDRESS="$_UNSET"
OUTPUT_DIR="$_UNSET"
PASSWORD_FILE=""
PBKDF2=false

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Generate Ethereum validator keys using rvc-keygen.
Any option not provided via flags will be prompted interactively.

Options:
  --network NAME            Network name: mainnet or hoodi (default: mainnet)
  --num-validators N        Number of validators to generate (default: 1)
  --withdrawal-address ADDR Execution address for 0x01 withdrawal credentials
  --output-dir DIR          Output directory (default: ./validator_keys)
  --password-file FILE      Read keystore password from file
  --pbkdf2                  Use PBKDF2 instead of Scrypt for keystore encryption
  -h, --help                Show this help message

Examples:
  # Interactive — prompts for everything
  $(basename "$0")

  # Fully non-interactive
  $(basename "$0") \\
    --network hoodi \\
    --num-validators 3 \\
    --withdrawal-address 0x71C7656EC7ab88b098defB751B7401B5f6d8976F \\
    --output-dir ./my_keys \\
    --password-file /tmp/pw.txt

  # Mix — provide some flags, prompted for the rest
  $(basename "$0") --network mainnet --num-validators 2
EOF
    exit 0
}

# Parse CLI flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --num-validators)
            NUM_VALIDATORS="$2"
            shift 2
            ;;
        --withdrawal-address)
            WITHDRAWAL_ADDRESS="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --password-file)
            PASSWORD_FILE="$2"
            shift 2
            ;;
        --pbkdf2)
            PBKDF2=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: Unknown option '$1'"
            echo "Run '$(basename "$0") --help' for usage."
            exit 1
            ;;
    esac
done

# Validation helpers
validate_network() {
    case "$1" in
        mainnet|hoodi) return 0 ;;
        *)
            echo "Error: Invalid network '$1'. Must be 'mainnet' or 'hoodi'."
            exit 1
            ;;
    esac
}

validate_num_validators() {
    if ! [[ "$1" =~ ^[1-9][0-9]*$ ]]; then
        echo "Error: Number of validators must be a positive integer, got '$1'."
        exit 1
    fi
}

validate_withdrawal_address() {
    if [[ -n "$1" ]]; then
        if ! [[ "$1" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
            echo "Error: Invalid withdrawal address '$1'."
            echo "  Must be '0x' followed by exactly 40 hex characters."
            exit 1
        fi
    fi
}

# Ensure rvc-keygen binary exists
if [[ ! -x "$KEYGEN_BIN" ]]; then
    echo "rvc-keygen binary not found at $KEYGEN_BIN"
    echo "Building rvc-keygen (release)..."
    (cd "$PROJECT_ROOT" && cargo build --release --bin rvc-keygen)
    if [[ ! -x "$KEYGEN_BIN" ]]; then
        echo "Error: Failed to build rvc-keygen."
        exit 1
    fi
    echo "Build complete."
    echo ""
fi

# Collect and validate each input (prompt if not provided via flag)
if [[ "$NETWORK" == "$_UNSET" ]]; then
    read -rp "Network (mainnet/hoodi) [mainnet]: " NETWORK
    NETWORK="${NETWORK:-mainnet}"
fi
validate_network "$NETWORK"

if [[ "$NUM_VALIDATORS" == "$_UNSET" ]]; then
    read -rp "Number of validators [1]: " NUM_VALIDATORS
    NUM_VALIDATORS="${NUM_VALIDATORS:-1}"
fi
validate_num_validators "$NUM_VALIDATORS"

if [[ "$WITHDRAWAL_ADDRESS" == "$_UNSET" ]]; then
    echo "Withdrawal address (0x-prefixed Ethereum address)."
    echo "  If provided, uses 0x01 (execution) withdrawal credentials."
    echo "  If left blank, uses 0x00 (BLS) withdrawal credentials."
    read -rp "Withdrawal address [none]: " WITHDRAWAL_ADDRESS
fi
validate_withdrawal_address "$WITHDRAWAL_ADDRESS"

if [[ "$OUTPUT_DIR" == "$_UNSET" ]]; then
    read -rp "Output directory [./validator_keys]: " OUTPUT_DIR
    OUTPUT_DIR="${OUTPUT_DIR:-./validator_keys}"
fi

if [[ -n "$PASSWORD_FILE" && ! -f "$PASSWORD_FILE" ]]; then
    echo "Error: Password file not found: $PASSWORD_FILE"
    exit 1
fi

# Build command
CMD=("$KEYGEN_BIN" new-mnemonic)
CMD+=(--network "$NETWORK")
CMD+=(--num-validators "$NUM_VALIDATORS")
CMD+=(--output-dir "$OUTPUT_DIR")

if [[ -n "$WITHDRAWAL_ADDRESS" ]]; then
    CMD+=(--withdrawal-address "$WITHDRAWAL_ADDRESS")
fi

if [[ -n "$PASSWORD_FILE" ]]; then
    CMD+=(--password-file "$PASSWORD_FILE")
fi

if [[ "$PBKDF2" == true ]]; then
    CMD+=(--pbkdf2)
fi

# Summary before execution
echo ""
echo "=== Validator Key Generation ==="
echo "  Network:            $NETWORK"
echo "  Validators:         $NUM_VALIDATORS"
if [[ -n "$WITHDRAWAL_ADDRESS" ]]; then
    echo "  Withdrawal address: $WITHDRAWAL_ADDRESS (0x01 credentials)"
else
    echo "  Withdrawal address: (none — 0x00 BLS credentials)"
fi
echo "  Output directory:   $OUTPUT_DIR"
echo "  Encryption:         $(if [[ "$PBKDF2" == true ]]; then echo "PBKDF2"; else echo "Scrypt (default)"; fi)"
if [[ -n "$PASSWORD_FILE" ]]; then
    echo "  Password:           from file ($PASSWORD_FILE)"
else
    echo "  Password:           will prompt"
fi
echo "================================"
echo ""

# Run rvc-keygen
"${CMD[@]}"

# Post-generation summary
echo ""
echo "=== Done ==="
if [[ -d "$OUTPUT_DIR" ]]; then
    echo "Generated files in $OUTPUT_DIR:"
    ls -1 "$OUTPUT_DIR"
fi
echo ""
echo "Next steps:"
echo "  1. Back up your mnemonic phrase securely (written down, never digital)."
echo "  2. Back up the keystore files and remember your password."
echo "  3. Submit the deposit_data JSON to the Ethereum Launchpad."
echo "  4. Import keystores into your validator client."
