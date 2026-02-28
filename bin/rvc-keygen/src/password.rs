use std::path::Path;

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

const MIN_PASSWORD_LENGTH: usize = 8;

/// Prompts the user for a password with double-prompt confirmation.
///
/// Returns `Zeroizing<String>` on success, or an error if the passwords don't match
/// or the password is too short.
pub fn prompt_password() -> Result<Zeroizing<String>> {
    let password = Zeroizing::new(
        rpassword::prompt_password_stderr("Enter keystore password: ")
            .context("Failed to read password")?,
    );

    validate_password(&password)?;

    let confirm = Zeroizing::new(
        rpassword::prompt_password_stderr("Confirm password: ")
            .context("Failed to read password")?,
    );

    if *password != *confirm {
        bail!("Passwords do not match");
    }

    Ok(password)
}

/// Reads a password from a file, trims trailing newlines.
#[allow(dead_code)]
pub fn read_password_file(path: &Path) -> Result<Zeroizing<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read password file: {}", path.display()))?;

    let password = content.trim_end_matches('\n').trim_end_matches('\r');
    validate_password(password)?;
    Ok(Zeroizing::new(password.to_string()))
}

/// Validates that a password meets minimum length requirements.
pub fn validate_password(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LENGTH {
        bail!(
            "Password too short: minimum {} characters, got {}",
            MIN_PASSWORD_LENGTH,
            password.len()
        );
    }
    Ok(())
}

/// Validates an Ethereum execution address (0x + 40 hex chars).
pub fn validate_address(addr: &str) -> Result<[u8; 20]> {
    if !addr.starts_with("0x") {
        bail!("Address must start with '0x', got '{}'", addr);
    }
    if addr.len() != 42 {
        bail!("Address must be 42 characters (0x + 40 hex), got {} characters", addr.len());
    }
    let bytes = hex::decode(&addr[2..])
        .with_context(|| format!("Address contains invalid hex characters: '{}'", addr))?;

    let mut result = [0u8; 20];
    result.copy_from_slice(&bytes);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_validate_password_minimum_length() {
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password("1234567890abcdef").is_ok());
    }

    #[test]
    fn test_validate_password_too_short() {
        assert!(validate_password("").is_err());
        assert!(validate_password("1234567").is_err());
        assert!(validate_password("abc").is_err());
    }

    #[test]
    fn test_validate_password_error_message() {
        let err = validate_password("short").unwrap_err();
        assert!(err.to_string().contains("minimum 8 characters"));
        assert!(err.to_string().contains("got 5"));
    }

    #[test]
    fn test_validate_address_valid() {
        let addr = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
        let result = validate_address(addr).unwrap();
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_validate_address_lowercase() {
        let addr = "0x71c7656ec7ab88b098defb751b7401b5f6d8976f";
        assert!(validate_address(addr).is_ok());
    }

    #[test]
    fn test_validate_address_missing_prefix() {
        let result = validate_address("71C7656EC7ab88b098defB751B7401B5f6d8976F");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must start with '0x'"));
    }

    #[test]
    fn test_validate_address_too_short() {
        let result = validate_address("0x71C7656EC7ab88b098");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("42 characters"));
    }

    #[test]
    fn test_validate_address_too_long() {
        let result = validate_address("0x71C7656EC7ab88b098defB751B7401B5f6d8976FAA");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_address_invalid_hex() {
        let result = validate_address("0xZZC7656EC7ab88b098defB751B7401B5f6d8976F");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid hex characters"));
    }

    #[test]
    fn test_validate_address_returns_bytes() {
        let addr = "0x0000000000000000000000000000000000000001";
        let bytes = validate_address(addr).unwrap();
        assert_eq!(bytes[19], 1);
        assert_eq!(bytes[0..19], [0u8; 19]);
    }

    #[test]
    fn test_read_password_file_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "mypassword123").unwrap();

        let password = read_password_file(&path).unwrap();
        assert_eq!(*password, "mypassword123");
    }

    #[test]
    fn test_read_password_file_no_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "mypassword123").unwrap();

        let password = read_password_file(&path).unwrap();
        assert_eq!(*password, "mypassword123");
    }

    #[test]
    fn test_read_password_file_windows_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "mypassword123\r\n").unwrap();

        let password = read_password_file(&path).unwrap();
        assert_eq!(*password, "mypassword123");
    }

    #[test]
    fn test_read_password_file_too_short() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "short\n").unwrap();

        let result = read_password_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_password_file_not_found() {
        let result = read_password_file(Path::new("/nonexistent/password.txt"));
        assert!(result.is_err());
    }
}
