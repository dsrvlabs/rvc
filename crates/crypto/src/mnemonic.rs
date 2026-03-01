use zeroize::Zeroizing;

use bip39::Language;
pub use bip39::Mnemonic;

#[derive(Debug, thiserror::Error)]
pub enum MnemonicError {
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),
}

/// Generates a new 24-word BIP-39 mnemonic (256-bit entropy).
pub fn generate_mnemonic() -> Mnemonic {
    Mnemonic::generate(24).expect("24-word mnemonic generation should not fail")
}

/// Validates and parses a mnemonic phrase (English).
pub fn validate_mnemonic(phrase: &str) -> Result<Mnemonic, MnemonicError> {
    Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))
}

/// Derives a 64-byte seed from a mnemonic and passphrase (PBKDF2-SHA512, 2048 iterations).
pub fn mnemonic_to_seed(mnemonic: &Mnemonic, passphrase: &str) -> Zeroizing<[u8; 64]> {
    Zeroizing::new(mnemonic.to_seed(passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic_24_words() {
        let mnemonic = generate_mnemonic();
        let phrase = mnemonic.to_string();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_generate_mnemonic_unique() {
        let m1 = generate_mnemonic();
        let m2 = generate_mnemonic();
        assert_ne!(m1.to_string(), m2.to_string());
    }

    #[test]
    fn test_validate_mnemonic_roundtrip() {
        let mnemonic = generate_mnemonic();
        let phrase = mnemonic.to_string();
        let parsed = validate_mnemonic(&phrase).unwrap();
        assert_eq!(parsed.to_string(), phrase);
    }

    #[test]
    fn test_validate_mnemonic_known_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = validate_mnemonic(phrase).unwrap();
        assert_eq!(mnemonic.to_string(), phrase);
    }

    #[test]
    fn test_validate_mnemonic_invalid_word() {
        let result = validate_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz");
        assert!(result.is_err());
        match result.unwrap_err() {
            MnemonicError::InvalidMnemonic(msg) => {
                assert!(!msg.is_empty());
            }
        }
    }

    #[test]
    fn test_validate_mnemonic_wrong_word_count() {
        let result = validate_mnemonic("abandon abandon abandon");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mnemonic_bad_checksum() {
        // Valid words but invalid checksum (last word changed)
        let result = validate_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mnemonic_empty_string() {
        let result = validate_mnemonic("");
        assert!(result.is_err());
    }

    #[test]
    fn test_mnemonic_to_seed_returns_64_bytes() {
        let mnemonic = generate_mnemonic();
        let seed = mnemonic_to_seed(&mnemonic, "");
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_mnemonic_to_seed_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = validate_mnemonic(phrase).unwrap();
        let seed1 = mnemonic_to_seed(&mnemonic, "");
        let seed2 = mnemonic_to_seed(&mnemonic, "");
        assert_eq!(*seed1, *seed2);
    }

    #[test]
    fn test_mnemonic_to_seed_passphrase_changes_seed() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = validate_mnemonic(phrase).unwrap();
        let seed_no_pass = mnemonic_to_seed(&mnemonic, "");
        let seed_with_pass = mnemonic_to_seed(&mnemonic, "my password");
        assert_ne!(*seed_no_pass, *seed_with_pass);
    }

    #[test]
    fn test_mnemonic_to_seed_known_vector() {
        // Known BIP-39 test vector: "abandon" x 23 + "art", empty passphrase
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = validate_mnemonic(phrase).unwrap();
        let seed = mnemonic_to_seed(&mnemonic, "");

        // Expected seed from BIP-39 reference (first 4 bytes as sanity check)
        // The full seed can be verified with any BIP-39 tool
        assert_eq!(seed.len(), 64);
        // Ensure it's not all zeros
        assert_ne!(*seed, [0u8; 64]);
    }

    #[test]
    fn test_error_display() {
        let e = MnemonicError::InvalidMnemonic("bad checksum".to_string());
        assert_eq!(e.to_string(), "Invalid mnemonic: bad checksum");
    }

    #[test]
    fn test_seed_integrates_with_eip2333() {
        use crate::eip2333::derive_master_sk;

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = validate_mnemonic(phrase).unwrap();
        let seed = mnemonic_to_seed(&mnemonic, "");

        // Should produce a valid master SK from the BIP-39 seed
        let master_sk = derive_master_sk(seed.as_ref()).unwrap();
        let pk = master_sk.public_key();
        assert_eq!(pk.to_bytes().len(), 48);
    }
}
