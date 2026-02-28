use anyhow::{bail, Result};
use eth_types::ForkSchedule;

#[derive(Debug)]
pub struct KeygenNetwork {
    pub name: &'static str,
    pub genesis_fork_version: [u8; 4],
    pub genesis_validators_root: [u8; 32],
    pub capella_fork_version: [u8; 4],
}

pub const MAINNET: KeygenNetwork = KeygenNetwork {
    name: "mainnet",
    genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
    genesis_validators_root: [
        0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd,
        0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b,
        0xfe, 0x95,
    ],
    capella_fork_version: [0x03, 0x00, 0x00, 0x00],
};

pub const HOODI: KeygenNetwork = KeygenNetwork {
    name: "hoodi",
    genesis_fork_version: [0x10, 0x00, 0x09, 0x10],
    genesis_validators_root: [
        0x21, 0x2f, 0x13, 0xfc, 0x4d, 0xf0, 0x78, 0xb6, 0xcb, 0x7d, 0xb2, 0x28, 0xf1, 0xc8, 0x30,
        0x75, 0x66, 0xdc, 0xec, 0xf9, 0x00, 0x86, 0x74, 0x01, 0xa9, 0x20, 0x23, 0xd7, 0xba, 0x99,
        0xcb, 0x5f,
    ],
    capella_fork_version: [0x40, 0x00, 0x09, 0x10],
};

pub fn from_name(name: &str) -> Result<&'static KeygenNetwork> {
    match name.to_lowercase().as_str() {
        "mainnet" => Ok(&MAINNET),
        "hoodi" => Ok(&HOODI),
        other => bail!("Unknown network: '{}'. Supported: mainnet, hoodi", other),
    }
}

/// Creates a `ForkSchedule` suitable for EIP-7044 voluntary exit signing.
///
/// Sets Capella as active at epoch 0 and all post-Capella forks at `u64::MAX`,
/// ensuring `ForkName::from_epoch()` never returns beyond Capella.
pub fn exit_fork_schedule(network: &KeygenNetwork) -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: network.genesis_fork_version,
        altair_fork_epoch: 0,
        altair_fork_version: network.genesis_fork_version,
        bellatrix_fork_epoch: 0,
        bellatrix_fork_version: network.genesis_fork_version,
        capella_fork_epoch: 0,
        capella_fork_version: network.capella_fork_version,
        deneb_fork_epoch: u64::MAX,
        deneb_fork_version: [0xFF, 0xFF, 0xFF, 0xFF],
        electra_fork_epoch: u64::MAX,
        electra_fork_version: [0xFF, 0xFF, 0xFF, 0xFF],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::ForkName;

    #[test]
    fn test_from_name_mainnet() {
        let net = from_name("mainnet").unwrap();
        assert_eq!(net.name, "mainnet");
        assert_eq!(net.genesis_fork_version, [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(net.capella_fork_version, [0x03, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_from_name_hoodi() {
        let net = from_name("hoodi").unwrap();
        assert_eq!(net.name, "hoodi");
        assert_eq!(net.genesis_fork_version, [0x10, 0x00, 0x09, 0x10]);
        assert_eq!(net.capella_fork_version, [0x40, 0x00, 0x09, 0x10]);
    }

    #[test]
    fn test_from_name_case_insensitive() {
        assert!(from_name("Mainnet").is_ok());
        assert!(from_name("HOODI").is_ok());
    }

    #[test]
    fn test_from_name_unknown() {
        let result = from_name("unknown");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown network"));
    }

    #[test]
    fn test_mainnet_genesis_root() {
        let expected =
            hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .unwrap();
        assert_eq!(MAINNET.genesis_validators_root, expected.as_slice());
    }

    #[test]
    fn test_hoodi_genesis_root() {
        let expected =
            hex::decode("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f")
                .unwrap();
        assert_eq!(HOODI.genesis_validators_root, expected.as_slice());
    }

    #[test]
    fn test_exit_fork_schedule_caps_at_capella() {
        let net = from_name("mainnet").unwrap();
        let schedule = exit_fork_schedule(net);

        // Any epoch should resolve to at most Capella
        assert_eq!(ForkName::from_epoch(0, &schedule), ForkName::Capella);
        assert_eq!(ForkName::from_epoch(1000, &schedule), ForkName::Capella);
        assert_eq!(ForkName::from_epoch(999999, &schedule), ForkName::Capella);
        assert_eq!(ForkName::from_epoch(u64::MAX - 1, &schedule), ForkName::Capella);
    }

    #[test]
    fn test_exit_fork_schedule_hoodi() {
        let net = from_name("hoodi").unwrap();
        let schedule = exit_fork_schedule(net);
        assert_eq!(schedule.capella_fork_version, [0x40, 0x00, 0x09, 0x10]);
        assert_eq!(ForkName::from_epoch(0, &schedule), ForkName::Capella);
    }
}
