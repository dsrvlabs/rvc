//! Network presets for Ethereum consensus networks.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Mainnet,
    Hoodi,
    Holesky,
    Sepolia,
    Custom,
}

impl Network {
    pub fn genesis_time(&self) -> Option<u64> {
        match self {
            Network::Mainnet => Some(1606824023),
            Network::Hoodi => Some(1742213400),
            Network::Holesky => Some(1695902400),
            Network::Sepolia => Some(1655733600),
            Network::Custom => None,
        }
    }

    pub fn genesis_validators_root(&self) -> Option<&'static str> {
        match self {
            Network::Mainnet => {
                Some("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
            }
            Network::Hoodi => {
                Some("0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f")
            }
            Network::Holesky => {
                Some("0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1")
            }
            Network::Sepolia => {
                Some("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
            }
            Network::Custom => None,
        }
    }

    pub fn seconds_per_slot(&self) -> u64 {
        12
    }

    pub fn slots_per_epoch(&self) -> u64 {
        32
    }
}

impl std::str::FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Network::Mainnet),
            "hoodi" => Ok(Network::Hoodi),
            "holesky" => Ok(Network::Holesky),
            "sepolia" => Ok(Network::Sepolia),
            "custom" => Ok(Network::Custom),
            _ => Err(format!("unknown network: {}", s)),
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Hoodi => write!(f, "hoodi"),
            Network::Holesky => write!(f, "holesky"),
            Network::Sepolia => write!(f, "sepolia"),
            Network::Custom => write!(f, "custom"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_genesis_time() {
        assert_eq!(Network::Mainnet.genesis_time(), Some(1606824023));
        assert_eq!(Network::Hoodi.genesis_time(), Some(1742213400));
        assert_eq!(Network::Custom.genesis_time(), None);
    }

    #[test]
    fn test_network_genesis_validators_root() {
        assert!(Network::Mainnet.genesis_validators_root().is_some());
        assert_eq!(
            Network::Hoodi.genesis_validators_root(),
            Some("0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f")
        );
        assert!(Network::Custom.genesis_validators_root().is_none());
    }

    #[test]
    fn test_network_from_str() {
        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("MAINNET".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("hoodi".parse::<Network>().unwrap(), Network::Hoodi);
        assert_eq!("HOODI".parse::<Network>().unwrap(), Network::Hoodi);
        assert_eq!("custom".parse::<Network>().unwrap(), Network::Custom);
        assert!("unknown".parse::<Network>().is_err());
    }

    #[test]
    fn test_network_from_str_deprecated_networks_rejected() {
        assert!("goerli".parse::<Network>().is_err());
    }

    #[test]
    fn test_network_from_str_testnets_accepted() {
        assert_eq!("holesky".parse::<Network>().unwrap(), Network::Holesky);
        assert_eq!("HOLESKY".parse::<Network>().unwrap(), Network::Holesky);
        assert_eq!("sepolia".parse::<Network>().unwrap(), Network::Sepolia);
        assert_eq!("SEPOLIA".parse::<Network>().unwrap(), Network::Sepolia);
    }

    #[test]
    fn test_network_display() {
        assert_eq!(Network::Mainnet.to_string(), "mainnet");
        assert_eq!(Network::Hoodi.to_string(), "hoodi");
        assert_eq!(Network::Custom.to_string(), "custom");
    }

    #[test]
    fn test_network_serde() {
        let network = Network::Mainnet;
        let json = serde_json::to_string(&network).unwrap();
        assert_eq!(json, "\"mainnet\"");

        let parsed: Network = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Network::Mainnet);
    }

    #[test]
    fn test_network_serde_hoodi() {
        let network = Network::Hoodi;
        let json = serde_json::to_string(&network).unwrap();
        assert_eq!(json, "\"hoodi\"");

        let parsed: Network = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Network::Hoodi);
    }

    #[test]
    fn test_network_serde_deprecated_networks_rejected() {
        assert!(serde_json::from_str::<Network>("\"goerli\"").is_err());
    }

    #[test]
    fn test_network_serde_testnets() {
        let holesky = Network::Holesky;
        let json = serde_json::to_string(&holesky).unwrap();
        assert_eq!(json, "\"holesky\"");
        let parsed: Network = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Network::Holesky);

        let sepolia = Network::Sepolia;
        let json = serde_json::to_string(&sepolia).unwrap();
        assert_eq!(json, "\"sepolia\"");
        let parsed: Network = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Network::Sepolia);
    }

    #[test]
    fn test_network_genesis_constants_holesky() {
        assert_eq!(Network::Holesky.genesis_time(), Some(1695902400));
        assert_eq!(
            Network::Holesky.genesis_validators_root(),
            Some("0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1")
        );
    }

    #[test]
    fn test_network_genesis_constants_sepolia() {
        assert_eq!(Network::Sepolia.genesis_time(), Some(1655733600));
        assert_eq!(
            Network::Sepolia.genesis_validators_root(),
            Some("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
        );
    }

    #[test]
    fn test_network_constants() {
        assert_eq!(Network::Mainnet.seconds_per_slot(), 12);
        assert_eq!(Network::Mainnet.slots_per_epoch(), 32);
    }
}
