use serde::{Deserialize, Serialize};

/// Block selection strategy for validator proposals.
///
/// Controls how the validator client chooses between local (execution) and
/// builder (MEV) blocks when producing a proposal.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockSelectionMode {
    /// Request both sources, select highest value (default behavior).
    /// Uses configured `builder_boost_factor`.
    #[default]
    MaxProfit,
    /// Never request builder blocks. Sets `builder_boost_factor=0`.
    ExecutionOnly,
    /// Always use builder; fall back to local on failure.
    /// Sets `builder_boost_factor=u64::MAX`.
    BuilderAlways,
    /// Always use builder; never fall back to local.
    /// If builder fails or circuit breaker trips, the proposal fails.
    /// Designed for DVT clusters where all members must propose the same block.
    BuilderOnly,
}

impl std::fmt::Display for BlockSelectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MaxProfit => write!(f, "max-profit"),
            Self::ExecutionOnly => write!(f, "execution-only"),
            Self::BuilderAlways => write!(f, "builder-always"),
            Self::BuilderOnly => write!(f, "builder-only"),
        }
    }
}

impl std::str::FromStr for BlockSelectionMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "max-profit" | "maxprofit" => Ok(Self::MaxProfit),
            "execution-only" | "executiononly" => Ok(Self::ExecutionOnly),
            "builder-always" | "builderalways" => Ok(Self::BuilderAlways),
            "builder-only" | "builderonly" => Ok(Self::BuilderOnly),
            other => Err(format!(
                "unknown block selection mode '{}': expected one of max-profit, execution-only, builder-always, builder-only",
                other
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_max_profit() {
        assert_eq!(BlockSelectionMode::default(), BlockSelectionMode::MaxProfit);
    }

    #[test]
    fn test_serde_roundtrip_json() {
        let modes = [
            BlockSelectionMode::MaxProfit,
            BlockSelectionMode::ExecutionOnly,
            BlockSelectionMode::BuilderAlways,
            BlockSelectionMode::BuilderOnly,
        ];
        for mode in &modes {
            let json = serde_json::to_string(mode).unwrap();
            let deserialized: BlockSelectionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, deserialized);
        }
    }

    #[test]
    fn test_serde_kebab_case_json() {
        assert_eq!(
            serde_json::to_string(&BlockSelectionMode::MaxProfit).unwrap(),
            "\"max-profit\""
        );
        assert_eq!(
            serde_json::to_string(&BlockSelectionMode::ExecutionOnly).unwrap(),
            "\"execution-only\""
        );
        assert_eq!(
            serde_json::to_string(&BlockSelectionMode::BuilderAlways).unwrap(),
            "\"builder-always\""
        );
        assert_eq!(
            serde_json::to_string(&BlockSelectionMode::BuilderOnly).unwrap(),
            "\"builder-only\""
        );
    }

    #[test]
    fn test_serde_roundtrip_toml() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Wrapper {
            mode: BlockSelectionMode,
        }

        let modes = [
            BlockSelectionMode::MaxProfit,
            BlockSelectionMode::ExecutionOnly,
            BlockSelectionMode::BuilderAlways,
            BlockSelectionMode::BuilderOnly,
        ];
        for mode in &modes {
            let wrapper = Wrapper { mode: *mode };
            let toml_str = toml::to_string(&wrapper).unwrap();
            let deserialized: Wrapper = toml::from_str(&toml_str).unwrap();
            assert_eq!(wrapper, deserialized);
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(BlockSelectionMode::MaxProfit.to_string(), "max-profit");
        assert_eq!(BlockSelectionMode::ExecutionOnly.to_string(), "execution-only");
        assert_eq!(BlockSelectionMode::BuilderAlways.to_string(), "builder-always");
        assert_eq!(BlockSelectionMode::BuilderOnly.to_string(), "builder-only");
    }

    #[test]
    fn test_from_str() {
        assert_eq!(
            "max-profit".parse::<BlockSelectionMode>().unwrap(),
            BlockSelectionMode::MaxProfit
        );
        assert_eq!(
            "maxprofit".parse::<BlockSelectionMode>().unwrap(),
            BlockSelectionMode::MaxProfit
        );
        assert_eq!(
            "execution-only".parse::<BlockSelectionMode>().unwrap(),
            BlockSelectionMode::ExecutionOnly
        );
        assert_eq!(
            "builder-always".parse::<BlockSelectionMode>().unwrap(),
            BlockSelectionMode::BuilderAlways
        );
        assert_eq!(
            "builder-only".parse::<BlockSelectionMode>().unwrap(),
            BlockSelectionMode::BuilderOnly
        );
        assert!("invalid".parse::<BlockSelectionMode>().is_err());
    }
}
