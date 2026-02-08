use crate::{Epoch, Version};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ForkName {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
}

pub struct ForkSchedule {
    pub genesis_fork_version: Version,
    pub altair_fork_epoch: Epoch,
    pub altair_fork_version: Version,
    pub bellatrix_fork_epoch: Epoch,
    pub bellatrix_fork_version: Version,
    pub capella_fork_epoch: Epoch,
    pub capella_fork_version: Version,
    pub deneb_fork_epoch: Epoch,
    pub deneb_fork_version: Version,
    pub electra_fork_epoch: Epoch,
    pub electra_fork_version: Version,
}

impl ForkName {
    pub fn from_epoch(epoch: Epoch, schedule: &ForkSchedule) -> Self {
        if epoch >= schedule.electra_fork_epoch {
            Self::Electra
        } else if epoch >= schedule.deneb_fork_epoch {
            Self::Deneb
        } else if epoch >= schedule.capella_fork_epoch {
            Self::Capella
        } else if epoch >= schedule.bellatrix_fork_epoch {
            Self::Bellatrix
        } else if epoch >= schedule.altair_fork_epoch {
            Self::Altair
        } else {
            Self::Phase0
        }
    }

    pub fn fork_version(&self, schedule: &ForkSchedule) -> Version {
        match self {
            Self::Phase0 => schedule.genesis_fork_version,
            Self::Altair => schedule.altair_fork_version,
            Self::Bellatrix => schedule.bellatrix_fork_version,
            Self::Capella => schedule.capella_fork_version,
            Self::Deneb => schedule.deneb_fork_version,
            Self::Electra => schedule.electra_fork_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 74240,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 144896,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 194048,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 269568,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 364544,
            electra_fork_version: [5, 0, 0, 0],
        }
    }

    #[test]
    fn test_fork_name_from_epoch_phase0() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(0, &schedule), ForkName::Phase0);
    }

    #[test]
    fn test_fork_name_from_epoch_altair_boundary() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(74239, &schedule), ForkName::Phase0);
        assert_eq!(ForkName::from_epoch(74240, &schedule), ForkName::Altair);
    }

    #[test]
    fn test_fork_name_from_epoch_bellatrix_boundary() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(144895, &schedule), ForkName::Altair);
        assert_eq!(ForkName::from_epoch(144896, &schedule), ForkName::Bellatrix);
    }

    #[test]
    fn test_fork_name_from_epoch_capella_boundary() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(194047, &schedule), ForkName::Bellatrix);
        assert_eq!(ForkName::from_epoch(194048, &schedule), ForkName::Capella);
    }

    #[test]
    fn test_fork_name_from_epoch_deneb_boundary() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(269567, &schedule), ForkName::Capella);
        assert_eq!(ForkName::from_epoch(269568, &schedule), ForkName::Deneb);
    }

    #[test]
    fn test_fork_name_from_epoch_electra_boundary() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(364543, &schedule), ForkName::Deneb);
        assert_eq!(ForkName::from_epoch(364544, &schedule), ForkName::Electra);
    }

    #[test]
    fn test_fork_name_from_epoch_far_future() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(u64::MAX, &schedule), ForkName::Electra);
    }

    #[test]
    fn test_fork_name_from_epoch_unscheduled_forks() {
        let schedule = ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 10,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: u64::MAX,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: u64::MAX,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: u64::MAX,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: u64::MAX,
            electra_fork_version: [5, 0, 0, 0],
        };
        assert_eq!(ForkName::from_epoch(0, &schedule), ForkName::Phase0);
        assert_eq!(ForkName::from_epoch(10, &schedule), ForkName::Altair);
        assert_eq!(ForkName::from_epoch(1_000_000, &schedule), ForkName::Altair);
    }

    #[test]
    fn test_fork_version_phase0() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Phase0.fork_version(&schedule), [0, 0, 0, 0]);
    }

    #[test]
    fn test_fork_version_altair() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Altair.fork_version(&schedule), [1, 0, 0, 0]);
    }

    #[test]
    fn test_fork_version_bellatrix() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Bellatrix.fork_version(&schedule), [2, 0, 0, 0]);
    }

    #[test]
    fn test_fork_version_capella() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Capella.fork_version(&schedule), [3, 0, 0, 0]);
    }

    #[test]
    fn test_fork_version_deneb() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Deneb.fork_version(&schedule), [4, 0, 0, 0]);
    }

    #[test]
    fn test_fork_version_electra() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Electra.fork_version(&schedule), [5, 0, 0, 0]);
    }

    #[test]
    fn test_fork_name_ordering() {
        assert!(ForkName::Phase0 < ForkName::Altair);
        assert!(ForkName::Altair < ForkName::Bellatrix);
        assert!(ForkName::Bellatrix < ForkName::Capella);
        assert!(ForkName::Capella < ForkName::Deneb);
        assert!(ForkName::Deneb < ForkName::Electra);
    }

    #[test]
    fn test_fork_name_equality() {
        assert_eq!(ForkName::Phase0, ForkName::Phase0);
        assert_ne!(ForkName::Phase0, ForkName::Altair);
    }
}
