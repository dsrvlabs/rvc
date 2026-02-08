#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub pubkey: [u8; 48],
    pub fee_recipient: Option<[u8; 20]>,
    pub gas_limit: Option<u64>,
    pub builder_proposals: bool,
    pub builder_boost_factor: u64,
    pub graffiti: Option<[u8; 32]>,
    pub enabled: bool,
}

impl ValidatorConfig {
    pub fn new(pubkey: [u8; 48]) -> Self {
        Self {
            pubkey,
            fee_recipient: None,
            gas_limit: None,
            builder_proposals: false,
            builder_boost_factor: 100,
            graffiti: None,
            enabled: true,
        }
    }
}

#[derive(Debug, Default)]
pub struct ValidatorConfigUpdate {
    pub fee_recipient: Option<Option<[u8; 20]>>,
    pub gas_limit: Option<Option<u64>>,
    pub graffiti: Option<Option<[u8; 32]>>,
    pub builder_proposals: Option<bool>,
    pub builder_boost_factor: Option<u64>,
}
