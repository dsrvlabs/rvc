//! Network presets for Ethereum consensus networks.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Mainnet,
    Goerli,
    Sepolia,
    Holesky,
    Custom,
}

impl Network {
    pub fn genesis_time(&self) -> Option<u64> {
        match self {
            Network::Mainnet => Some(1606824023),
            Network::Goerli => Some(1616508000),
            Network::Sepolia => Some(1655733600),
            Network::Holesky => Some(1695902400),
            Network::Custom => None,
        }
    }

    pub fn genesis_validators_root(&self) -> Option<&'static str> {
        match self {
            Network::Mainnet => {
                Some("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
            }
            Network::Goerli => {
                Some("0x043db0d9a83813551ee2f33450d23797757d430911a9320530ad8a0eabc43efb")
            }
            Network::Sepolia => {
                Some("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
            }
            Network::Holesky => {
                Some("0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1")
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
            "goerli" => Ok(Network::Goerli),
            "sepolia" => Ok(Network::Sepolia),
            "holesky" => Ok(Network::Holesky),
            "custom" => Ok(Network::Custom),
            _ => Err(format!("unknown network: {}", s)),
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Goerli => write!(f, "goerli"),
            Network::Sepolia => write!(f, "sepolia"),
            Network::Holesky => write!(f, "holesky"),
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
        assert_eq!(Network::Goerli.genesis_time(), Some(1616508000));
        assert_eq!(Network::Sepolia.genesis_time(), Some(1655733600));
        assert_eq!(Network::Holesky.genesis_time(), Some(1695902400));
        assert_eq!(Network::Custom.genesis_time(), None);
    }

    #[test]
    fn test_network_genesis_validators_root() {
        assert!(Network::Mainnet.genesis_validators_root().is_some());
        assert!(Network::Goerli.genesis_validators_root().is_some());
        assert!(Network::Sepolia.genesis_validators_root().is_some());
        assert!(Network::Holesky.genesis_validators_root().is_some());
        assert!(Network::Custom.genesis_validators_root().is_none());
    }

    #[test]
    fn test_network_from_str() {
        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("MAINNET".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("goerli".parse::<Network>().unwrap(), Network::Goerli);
        assert_eq!("sepolia".parse::<Network>().unwrap(), Network::Sepolia);
        assert_eq!("holesky".parse::<Network>().unwrap(), Network::Holesky);
        assert_eq!("custom".parse::<Network>().unwrap(), Network::Custom);
        assert!("unknown".parse::<Network>().is_err());
    }

    #[test]
    fn test_network_display() {
        assert_eq!(Network::Mainnet.to_string(), "mainnet");
        assert_eq!(Network::Goerli.to_string(), "goerli");
        assert_eq!(Network::Sepolia.to_string(), "sepolia");
        assert_eq!(Network::Holesky.to_string(), "holesky");
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
    fn test_network_constants() {
        assert_eq!(Network::Mainnet.seconds_per_slot(), 12);
        assert_eq!(Network::Mainnet.slots_per_epoch(), 32);
    }
}
