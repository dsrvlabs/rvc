//! Timing service error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TimingError {
    #[error("current time {current_time} is before genesis time {genesis_time}")]
    BeforeGenesis { current_time: u64, genesis_time: u64 },

    #[error("slot {slot} has not yet started")]
    SlotNotStarted { slot: u64 },

    #[error("timer cancelled")]
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_before_genesis_display() {
        let err = TimingError::BeforeGenesis { current_time: 100, genesis_time: 200 };
        assert_eq!(err.to_string(), "current time 100 is before genesis time 200");
    }

    #[test]
    fn test_slot_not_started_display() {
        let err = TimingError::SlotNotStarted { slot: 42 };
        assert_eq!(err.to_string(), "slot 42 has not yet started");
    }

    #[test]
    fn test_cancelled_display() {
        let err = TimingError::Cancelled;
        assert_eq!(err.to_string(), "timer cancelled");
    }
}
