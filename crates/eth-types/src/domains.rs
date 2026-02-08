use crate::DomainType;

pub const DOMAIN_BEACON_PROPOSER: DomainType = [0x00, 0x00, 0x00, 0x00];
pub const DOMAIN_BEACON_ATTESTER: DomainType = [0x01, 0x00, 0x00, 0x00];
pub const DOMAIN_RANDAO: DomainType = [0x02, 0x00, 0x00, 0x00];
pub const DOMAIN_DEPOSIT: DomainType = [0x03, 0x00, 0x00, 0x00];
pub const DOMAIN_VOLUNTARY_EXIT: DomainType = [0x04, 0x00, 0x00, 0x00];
pub const DOMAIN_SELECTION_PROOF: DomainType = [0x05, 0x00, 0x00, 0x00];
pub const DOMAIN_AGGREGATE_AND_PROOF: DomainType = [0x06, 0x00, 0x00, 0x00];
pub const DOMAIN_SYNC_COMMITTEE: DomainType = [0x07, 0x00, 0x00, 0x00];
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: DomainType = [0x08, 0x00, 0x00, 0x00];
pub const DOMAIN_CONTRIBUTION_AND_PROOF: DomainType = [0x09, 0x00, 0x00, 0x00];
pub const DOMAIN_APPLICATION_BUILDER: DomainType = [0x00, 0x00, 0x00, 0x01];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_beacon_proposer() {
        assert_eq!(DOMAIN_BEACON_PROPOSER, [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_domain_beacon_attester() {
        assert_eq!(DOMAIN_BEACON_ATTESTER, [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_domain_randao() {
        assert_eq!(DOMAIN_RANDAO, [0x02, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_domain_deposit() {
        assert_eq!(DOMAIN_DEPOSIT, [0x03, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_domain_voluntary_exit() {
        assert_eq!(DOMAIN_VOLUNTARY_EXIT, [0x04, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_domain_selection_proof() {
        assert_eq!(DOMAIN_SELECTION_PROOF, [0x05, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_domain_aggregate_and_proof() {
        assert_eq!(DOMAIN_AGGREGATE_AND_PROOF, [0x06, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_domain_sync_committee() {
        assert_eq!(DOMAIN_SYNC_COMMITTEE, [0x07, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_domain_sync_committee_selection_proof() {
        assert_eq!(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, [0x08, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_domain_contribution_and_proof() {
        assert_eq!(DOMAIN_CONTRIBUTION_AND_PROOF, [0x09, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_domain_application_builder() {
        assert_eq!(DOMAIN_APPLICATION_BUILDER, [0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn test_all_domains_are_unique() {
        let domains = [
            DOMAIN_BEACON_PROPOSER,
            DOMAIN_BEACON_ATTESTER,
            DOMAIN_RANDAO,
            DOMAIN_DEPOSIT,
            DOMAIN_VOLUNTARY_EXIT,
            DOMAIN_SELECTION_PROOF,
            DOMAIN_AGGREGATE_AND_PROOF,
            DOMAIN_SYNC_COMMITTEE,
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            DOMAIN_CONTRIBUTION_AND_PROOF,
            DOMAIN_APPLICATION_BUILDER,
        ];
        for i in 0..domains.len() {
            for j in (i + 1)..domains.len() {
                assert_ne!(domains[i], domains[j], "Domain {} and {} are identical", i, j);
            }
        }
    }

    #[test]
    fn test_domain_type_is_4_bytes() {
        assert_eq!(std::mem::size_of_val(&DOMAIN_BEACON_PROPOSER), 4);
    }
}
