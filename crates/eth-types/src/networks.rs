//! Named network presets (mainnet / hoodi / holesky / sepolia).
//!
//! Single source of truth for genesis fork version, genesis validators root (GVR),
//! Capella fork version, and genesis time. Byte fields are authoritative; hex
//! accessors format those bytes so no hex literal is written twice.
//!
//! Consumers (keygen, rvc config) adopt this table in RF3-04. `Custom` is not
//! modelled here — it is an `Option`-returning concern on the rvc side.

use crate::{Root, Version};

/// Consensus network identity constants used for signing-domain construction
/// and genesis-parameter resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkPreset {
    pub name: &'static str,
    pub genesis_fork_version: Version,
    pub genesis_validators_root: Root,
    pub capella_fork_version: Version,
    pub genesis_time: u64,
}

impl NetworkPreset {
    /// Ethereum mainnet.
    pub const MAINNET: Self = Self {
        name: "mainnet",
        genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
        genesis_validators_root: [
            0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f,
            0xdd, 0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f,
            0x51, 0x1b, 0xfe, 0x95,
        ],
        capella_fork_version: [0x03, 0x00, 0x00, 0x00],
        genesis_time: 1606824023,
    };

    /// Hoodi testnet.
    pub const HOODI: Self = Self {
        name: "hoodi",
        genesis_fork_version: [0x10, 0x00, 0x09, 0x10],
        genesis_validators_root: [
            0x21, 0x2f, 0x13, 0xfc, 0x4d, 0xf0, 0x78, 0xb6, 0xcb, 0x7d, 0xb2, 0x28, 0xf1, 0xc8,
            0x30, 0x75, 0x66, 0xdc, 0xec, 0xf9, 0x00, 0x86, 0x74, 0x01, 0xa9, 0x20, 0x23, 0xd7,
            0xba, 0x99, 0xcb, 0x5f,
        ],
        capella_fork_version: [0x40, 0x00, 0x09, 0x10],
        genesis_time: 1742213400,
    };

    /// Holesky testnet.
    pub const HOLESKY: Self = Self {
        name: "holesky",
        genesis_fork_version: [0x01, 0x01, 0x70, 0x00],
        genesis_validators_root: [
            0x91, 0x43, 0xaa, 0x7c, 0x61, 0x5a, 0x7f, 0x71, 0x15, 0xe2, 0xb6, 0xaa, 0xc3, 0x19,
            0xc0, 0x35, 0x29, 0xdf, 0x82, 0x42, 0xae, 0x70, 0x5f, 0xba, 0x9d, 0xf3, 0x9b, 0x79,
            0xc5, 0x9f, 0xa8, 0xb1,
        ],
        capella_fork_version: [0x04, 0x01, 0x70, 0x00],
        genesis_time: 1695902400,
    };

    /// Sepolia testnet.
    pub const SEPOLIA: Self = Self {
        name: "sepolia",
        genesis_fork_version: [0x90, 0x00, 0x00, 0x69],
        genesis_validators_root: [
            0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61,
            0x05, 0x2a, 0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09,
            0xed, 0x9b, 0x80, 0x78,
        ],
        capella_fork_version: [0x90, 0x00, 0x00, 0x72],
        genesis_time: 1655733600,
    };

    /// Lowercase `0x`-prefixed hex of [`Self::genesis_validators_root`].
    ///
    /// Derived from the byte constant — never a second literal.
    pub fn genesis_validators_root_hex(&self) -> String {
        format!("0x{}", hex::encode(self.genesis_validators_root))
    }

    /// Lowercase `0x`-prefixed hex of [`Self::genesis_fork_version`].
    ///
    /// Derived from the byte constant — never a second literal.
    pub fn genesis_fork_version_hex(&self) -> String {
        format!("0x{}", hex::encode(self.genesis_fork_version))
    }

    /// Lowercase `0x`-prefixed hex of [`Self::capella_fork_version`].
    ///
    /// Derived from the byte constant — never a second literal.
    pub fn capella_fork_version_hex(&self) -> String {
        format!("0x{}", hex::encode(self.capella_fork_version))
    }
}

/// Module-level aliases matching the historical free-const style in keygen.
pub const MAINNET: NetworkPreset = NetworkPreset::MAINNET;
pub const HOODI: NetworkPreset = NetworkPreset::HOODI;
pub const HOLESKY: NetworkPreset = NetworkPreset::HOLESKY;
pub const SEPOLIA: NetworkPreset = NetworkPreset::SEPOLIA;

/// All known named presets, in declaration order.
pub const ALL: &[&NetworkPreset] = &[
    &NetworkPreset::MAINNET,
    &NetworkPreset::HOODI,
    &NetworkPreset::HOLESKY,
    &NetworkPreset::SEPOLIA,
];

/// Resolve a named preset by case-insensitive name.
///
/// Returns `None` for unknown names (including `"custom"` — that is not a preset).
pub fn from_name(name: &str) -> Option<&'static NetworkPreset> {
    let lower = name.to_ascii_lowercase();
    ALL.iter().copied().find(|p| p.name == lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // KAT anchors — copy-pasted from the two existing sources of truth.
    // Write by paste only; never retype. These pin RF3-03 against drift.
    // ---------------------------------------------------------------------------

    /// Byte literals copied from `bin/rvc-keygen/src/network.rs`.
    struct KeygenKat {
        name: &'static str,
        genesis_fork_version: [u8; 4],
        genesis_validators_root: [u8; 32],
        capella_fork_version: [u8; 4],
    }

    /// Hex + genesis_time literals copied from `crates/rvc/src/config/network.rs`.
    struct RvcKat {
        name: &'static str,
        genesis_validators_root_hex: &'static str,
        genesis_time: u64,
    }

    const KEYGEN_KATS: &[KeygenKat] = &[
        KeygenKat {
            name: "mainnet",
            genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
            genesis_validators_root: [
                0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f,
                0xdd, 0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f,
                0x51, 0x1b, 0xfe, 0x95,
            ],
            capella_fork_version: [0x03, 0x00, 0x00, 0x00],
        },
        KeygenKat {
            name: "hoodi",
            genesis_fork_version: [0x10, 0x00, 0x09, 0x10],
            genesis_validators_root: [
                0x21, 0x2f, 0x13, 0xfc, 0x4d, 0xf0, 0x78, 0xb6, 0xcb, 0x7d, 0xb2, 0x28, 0xf1, 0xc8,
                0x30, 0x75, 0x66, 0xdc, 0xec, 0xf9, 0x00, 0x86, 0x74, 0x01, 0xa9, 0x20, 0x23, 0xd7,
                0xba, 0x99, 0xcb, 0x5f,
            ],
            capella_fork_version: [0x40, 0x00, 0x09, 0x10],
        },
        KeygenKat {
            name: "holesky",
            genesis_fork_version: [0x01, 0x01, 0x70, 0x00],
            genesis_validators_root: [
                0x91, 0x43, 0xaa, 0x7c, 0x61, 0x5a, 0x7f, 0x71, 0x15, 0xe2, 0xb6, 0xaa, 0xc3, 0x19,
                0xc0, 0x35, 0x29, 0xdf, 0x82, 0x42, 0xae, 0x70, 0x5f, 0xba, 0x9d, 0xf3, 0x9b, 0x79,
                0xc5, 0x9f, 0xa8, 0xb1,
            ],
            capella_fork_version: [0x04, 0x01, 0x70, 0x00],
        },
        KeygenKat {
            name: "sepolia",
            genesis_fork_version: [0x90, 0x00, 0x00, 0x69],
            genesis_validators_root: [
                0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61,
                0x05, 0x2a, 0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09,
                0xed, 0x9b, 0x80, 0x78,
            ],
            capella_fork_version: [0x90, 0x00, 0x00, 0x72],
        },
    ];

    const RVC_KATS: &[RvcKat] = &[
        RvcKat {
            name: "mainnet",
            genesis_validators_root_hex:
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            genesis_time: 1606824023,
        },
        RvcKat {
            name: "hoodi",
            genesis_validators_root_hex:
                "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
            genesis_time: 1742213400,
        },
        RvcKat {
            name: "holesky",
            genesis_validators_root_hex:
                "0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1",
            genesis_time: 1695902400,
        },
        RvcKat {
            name: "sepolia",
            genesis_validators_root_hex:
                "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
            genesis_time: 1655733600,
        },
    ];

    #[test]
    fn test_preset_hex_accessor_matches_keygen_byte_literal() {
        assert_eq!(KEYGEN_KATS.len(), 4);
        assert_eq!(ALL.len(), 4);

        for kat in KEYGEN_KATS {
            let preset = from_name(kat.name).expect("preset must exist for keygen KAT name");
            assert_eq!(
                preset.genesis_validators_root, kat.genesis_validators_root,
                "GVR bytes mismatch for {}",
                kat.name
            );
            assert_eq!(
                preset.genesis_fork_version, kat.genesis_fork_version,
                "genesis fork version mismatch for {}",
                kat.name
            );
            assert_eq!(
                preset.capella_fork_version, kat.capella_fork_version,
                "capella fork version mismatch for {}",
                kat.name
            );
        }

        for kat in RVC_KATS {
            let preset = from_name(kat.name).expect("preset must exist for rvc KAT name");
            assert_eq!(
                preset.genesis_validators_root_hex(),
                kat.genesis_validators_root_hex,
                "GVR hex accessor mismatch for {}",
                kat.name
            );
        }
    }

    #[test]
    fn test_genesis_time_matches_rvc_config_literals() {
        for kat in RVC_KATS {
            let preset = from_name(kat.name).expect("preset must exist");
            assert_eq!(
                preset.genesis_time, kat.genesis_time,
                "genesis_time mismatch for {}",
                kat.name
            );
        }
    }

    #[test]
    fn test_from_name_is_case_insensitive_and_rejects_unknown() {
        assert_eq!(from_name("mainnet").map(|p| p.name), Some("mainnet"));
        assert_eq!(from_name("MAINNET").map(|p| p.name), Some("mainnet"));
        assert_eq!(from_name("MainNet").map(|p| p.name), Some("mainnet"));
        assert_eq!(from_name("hoodi").map(|p| p.name), Some("hoodi"));
        assert_eq!(from_name("HOODI").map(|p| p.name), Some("hoodi"));
        assert_eq!(from_name("holesky").map(|p| p.name), Some("holesky"));
        assert_eq!(from_name("HOLESKY").map(|p| p.name), Some("holesky"));
        assert_eq!(from_name("sepolia").map(|p| p.name), Some("sepolia"));
        assert_eq!(from_name("SEPOLIA").map(|p| p.name), Some("sepolia"));

        assert!(from_name("unknown").is_none());
        assert!(from_name("custom").is_none());
        assert!(from_name("goerli").is_none());
        assert!(from_name("").is_none());
    }

    #[test]
    fn test_all_networks_have_distinct_gvr() {
        let mut seen = std::collections::HashSet::new();
        for preset in ALL {
            assert!(
                seen.insert(preset.genesis_validators_root),
                "duplicate GVR for network {}",
                preset.name
            );
        }
        assert_eq!(seen.len(), ALL.len());
    }

    #[test]
    fn test_hex_accessors_are_derived_from_bytes() {
        for preset in ALL {
            let expected_gvr = format!("0x{}", hex::encode(preset.genesis_validators_root));
            let expected_genesis_fv = format!("0x{}", hex::encode(preset.genesis_fork_version));
            let expected_capella_fv = format!("0x{}", hex::encode(preset.capella_fork_version));
            assert_eq!(preset.genesis_validators_root_hex(), expected_gvr);
            assert_eq!(preset.genesis_fork_version_hex(), expected_genesis_fv);
            assert_eq!(preset.capella_fork_version_hex(), expected_capella_fv);
            assert!(preset.genesis_validators_root_hex().starts_with("0x"));
            assert_eq!(preset.genesis_validators_root_hex().len(), 2 + 64);
            assert_eq!(preset.genesis_fork_version_hex().len(), 2 + 8);
        }
    }

    #[test]
    fn test_all_lists_every_named_const() {
        assert_eq!(ALL.len(), 4);
        assert_eq!(*ALL[0], NetworkPreset::MAINNET);
        assert_eq!(*ALL[1], NetworkPreset::HOODI);
        assert_eq!(*ALL[2], NetworkPreset::HOLESKY);
        assert_eq!(*ALL[3], NetworkPreset::SEPOLIA);
        // Free aliases match associated consts.
        assert_eq!(MAINNET, NetworkPreset::MAINNET);
        assert_eq!(HOODI, NetworkPreset::HOODI);
        assert_eq!(HOLESKY, NetworkPreset::HOLESKY);
        assert_eq!(SEPOLIA, NetworkPreset::SEPOLIA);
    }
}
