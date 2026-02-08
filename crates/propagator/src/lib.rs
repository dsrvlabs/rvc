//! Propagator service for submitting attestations to the beacon node.
//!
//! This module provides the [`Propagator`] service which handles submitting
//! signed attestations to the beacon node's attestation pool.

mod error;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tracing::{debug, info, warn};

use beacon::{Attestation, BeaconClient, BeaconError, SubmitAttestationResult};
use metrics::definitions::{attestation_status, RVC_ATTESTATIONS_TOTAL};

pub use error::PropagatorError;

/// Trait for attestation submission, enabling dependency injection for testing.
pub trait AttestationSubmitter: Send + Sync {
    fn submit_attestation<'a>(
        &'a self,
        attestations: &'a [Attestation],
    ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>;
}

impl AttestationSubmitter for BeaconClient {
    fn submit_attestation<'a>(
        &'a self,
        attestations: &'a [Attestation],
    ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>
    {
        Box::pin(async move { BeaconClient::submit_attestation(self, attestations).await })
    }
}

/// Result of a propagation operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropagationResult {
    pub total: usize,
    pub success_count: usize,
    pub failure_count: usize,
}

impl PropagationResult {
    pub fn is_success(&self) -> bool {
        self.failure_count == 0 && self.total > 0
    }

    pub fn is_partial_success(&self) -> bool {
        self.success_count > 0 && self.failure_count > 0
    }

    pub fn is_complete_failure(&self) -> bool {
        self.total > 0 && self.success_count == 0
    }
}

/// Service responsible for propagating attestations to the beacon node.
pub struct Propagator<S: AttestationSubmitter> {
    submitter: Arc<S>,
}

impl<S: AttestationSubmitter> Propagator<S> {
    pub fn new(submitter: Arc<S>) -> Self {
        Self { submitter }
    }

    /// Propagates a single attestation to the beacon node.
    pub async fn propagate(&self, attestation: Attestation) -> Result<(), PropagatorError> {
        self.propagate_batch(&[attestation]).await?;
        Ok(())
    }

    /// Propagates multiple attestations to the beacon node in a single batch.
    pub async fn propagate_batch(
        &self,
        attestations: &[Attestation],
    ) -> Result<PropagationResult, PropagatorError> {
        if attestations.is_empty() {
            debug!("No attestations to propagate");
            return Ok(PropagationResult { total: 0, success_count: 0, failure_count: 0 });
        }

        let total = attestations.len();
        debug!(count = total, "Propagating attestations to beacon node");

        let result = self.submitter.submit_attestation(attestations).await?;

        match result {
            SubmitAttestationResult::Success => {
                info!(count = total, "Successfully propagated all attestations");
                RVC_ATTESTATIONS_TOTAL
                    .with_label_values(&[attestation_status::SUCCESS])
                    .inc_by(total as u64);

                Ok(PropagationResult { total, success_count: total, failure_count: 0 })
            }
            SubmitAttestationResult::PartialFailure { failures } => {
                let failure_count = failures.len();
                let success_count = total.saturating_sub(failure_count);

                if failure_count == 0 {
                    info!(count = total, "Successfully propagated all attestations");
                    RVC_ATTESTATIONS_TOTAL
                        .with_label_values(&[attestation_status::SUCCESS])
                        .inc_by(total as u64);
                    return Ok(PropagationResult { total, success_count: total, failure_count: 0 });
                }

                for failure in &failures {
                    warn!(
                        index = failure.index,
                        message = %failure.message,
                        "Attestation failed validation"
                    );
                }

                RVC_ATTESTATIONS_TOTAL
                    .with_label_values(&[attestation_status::SUCCESS])
                    .inc_by(success_count as u64);
                RVC_ATTESTATIONS_TOTAL
                    .with_label_values(&[attestation_status::FAILED])
                    .inc_by(failure_count as u64);

                if success_count == 0 {
                    Err(PropagatorError::AllAttestationsFailed)
                } else {
                    Err(PropagatorError::PartialFailure { success_count, failure_count })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use beacon::{AttestationData, Checkpoint, IndexedAttestationError};

    struct MockSubmitter {
        result: tokio::sync::Mutex<SubmitAttestationResult>,
        call_count: AtomicUsize,
        should_error: tokio::sync::Mutex<Option<BeaconError>>,
    }

    impl MockSubmitter {
        fn new(result: SubmitAttestationResult) -> Self {
            Self {
                result: tokio::sync::Mutex::new(result),
                call_count: AtomicUsize::new(0),
                should_error: tokio::sync::Mutex::new(None),
            }
        }

        fn with_error(error: BeaconError) -> Self {
            Self {
                result: tokio::sync::Mutex::new(SubmitAttestationResult::Success),
                call_count: AtomicUsize::new(0),
                should_error: tokio::sync::Mutex::new(Some(error)),
            }
        }

        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    impl AttestationSubmitter for MockSubmitter {
        fn submit_attestation<'a>(
            &'a self,
            _attestations: &'a [Attestation],
        ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.call_count.fetch_add(1, Ordering::SeqCst);

                let maybe_error = self.should_error.lock().await;
                if let Some(ref error) = *maybe_error {
                    return Err(match error {
                        BeaconError::Timeout => BeaconError::Timeout,
                        BeaconError::HttpError(msg) => BeaconError::HttpError(msg.clone()),
                        BeaconError::ApiError { status, message } => {
                            BeaconError::ApiError { status: *status, message: message.clone() }
                        }
                        BeaconError::ParseError(msg) => BeaconError::ParseError(msg.clone()),
                        BeaconError::InvalidUrl(msg) => BeaconError::InvalidUrl(msg.clone()),
                    });
                }

                let result = self.result.lock().await;
                Ok(result.clone())
            })
        }
    }

    fn create_test_attestation(slot: &str, index: &str) -> Attestation {
        Attestation {
            committee_index: index.parse().unwrap_or(0),
            attester_index: 0,
            data: AttestationData {
                slot: slot.to_string(),
                index: index.to_string(),
                beacon_block_root:
                    "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                source: Checkpoint {
                    epoch: "100".to_string(),
                    root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                },
                target: Checkpoint {
                    epoch: "101".to_string(),
                    root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                },
            },
            signature: "0xsignature".to_string(),
        }
    }

    #[tokio::test]
    async fn test_propagator_new() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let _propagator = Propagator::new(submitter);
    }

    #[tokio::test]
    async fn test_propagate_single_success() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let propagator = Propagator::new(submitter.clone());

        let attestation = create_test_attestation("1000", "1");
        let result = propagator.propagate(attestation).await;

        assert!(result.is_ok());
        assert_eq!(submitter.call_count(), 1);
    }

    #[tokio::test]
    async fn test_propagate_batch_success() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let propagator = Propagator::new(submitter.clone());

        let attestations =
            vec![create_test_attestation("1000", "1"), create_test_attestation("1000", "2")];

        let result = propagator.propagate_batch(&attestations).await.unwrap();

        assert!(result.is_success());
        assert_eq!(result.total, 2);
        assert_eq!(result.success_count, 2);
        assert_eq!(result.failure_count, 0);
        assert_eq!(submitter.call_count(), 1);
    }

    #[tokio::test]
    async fn test_propagate_batch_empty() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let propagator = Propagator::new(submitter.clone());

        let attestations: Vec<Attestation> = vec![];
        let result = propagator.propagate_batch(&attestations).await.unwrap();

        assert_eq!(result.total, 0);
        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 0);
        assert!(!result.is_success());
        assert_eq!(submitter.call_count(), 0);
    }

    #[tokio::test]
    async fn test_propagate_batch_partial_failure() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::PartialFailure {
            failures: vec![IndexedAttestationError {
                index: 1,
                message: "Invalid signature".to_string(),
            }],
        }));
        let propagator = Propagator::new(submitter.clone());

        let attestations = vec![
            create_test_attestation("1000", "1"),
            create_test_attestation("1000", "2"),
            create_test_attestation("1000", "3"),
        ];

        let result = propagator.propagate_batch(&attestations).await;

        match result {
            Err(PropagatorError::PartialFailure { success_count, failure_count }) => {
                assert_eq!(success_count, 2);
                assert_eq!(failure_count, 1);
            }
            _ => panic!("Expected PartialFailure error"),
        }
    }

    #[tokio::test]
    async fn test_propagate_batch_all_failed() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::PartialFailure {
            failures: vec![
                IndexedAttestationError { index: 0, message: "Invalid signature".to_string() },
                IndexedAttestationError { index: 1, message: "Attestation too old".to_string() },
            ],
        }));
        let propagator = Propagator::new(submitter.clone());

        let attestations =
            vec![create_test_attestation("1000", "1"), create_test_attestation("1000", "2")];

        let result = propagator.propagate_batch(&attestations).await;

        assert!(matches!(result, Err(PropagatorError::AllAttestationsFailed)));
    }

    #[tokio::test]
    async fn test_propagate_beacon_error() {
        let submitter = Arc::new(MockSubmitter::with_error(BeaconError::Timeout));
        let propagator = Propagator::new(submitter.clone());

        let attestation = create_test_attestation("1000", "1");
        let result = propagator.propagate(attestation).await;

        assert!(matches!(result, Err(PropagatorError::BeaconError(_))));
    }

    #[tokio::test]
    async fn test_propagate_http_error() {
        let submitter = Arc::new(MockSubmitter::with_error(BeaconError::HttpError(
            "connection refused".to_string(),
        )));
        let propagator = Propagator::new(submitter.clone());

        let attestation = create_test_attestation("1000", "1");
        let result = propagator.propagate(attestation).await;

        match result {
            Err(PropagatorError::BeaconError(BeaconError::HttpError(msg))) => {
                assert_eq!(msg, "connection refused");
            }
            _ => panic!("Expected HttpError"),
        }
    }

    #[tokio::test]
    async fn test_propagate_api_error() {
        let submitter = Arc::new(MockSubmitter::with_error(BeaconError::ApiError {
            status: 503,
            message: "Service unavailable".to_string(),
        }));
        let propagator = Propagator::new(submitter.clone());

        let attestation = create_test_attestation("1000", "1");
        let result = propagator.propagate(attestation).await;

        match result {
            Err(PropagatorError::BeaconError(BeaconError::ApiError { status, message })) => {
                assert_eq!(status, 503);
                assert_eq!(message, "Service unavailable");
            }
            _ => panic!("Expected ApiError"),
        }
    }

    #[tokio::test]
    async fn test_propagation_result_is_success() {
        let result = PropagationResult { total: 5, success_count: 5, failure_count: 0 };
        assert!(result.is_success());
        assert!(!result.is_partial_success());
        assert!(!result.is_complete_failure());
    }

    #[tokio::test]
    async fn test_propagation_result_is_partial_success() {
        let result = PropagationResult { total: 5, success_count: 3, failure_count: 2 };
        assert!(!result.is_success());
        assert!(result.is_partial_success());
        assert!(!result.is_complete_failure());
    }

    #[tokio::test]
    async fn test_propagation_result_is_complete_failure() {
        let result = PropagationResult { total: 5, success_count: 0, failure_count: 5 };
        assert!(!result.is_success());
        assert!(!result.is_partial_success());
        assert!(result.is_complete_failure());
    }

    #[tokio::test]
    async fn test_propagation_result_empty() {
        let result = PropagationResult { total: 0, success_count: 0, failure_count: 0 };
        assert!(!result.is_success());
        assert!(!result.is_partial_success());
        assert!(!result.is_complete_failure());
    }

    #[tokio::test]
    async fn test_propagate_batch_partial_failure_with_empty_failures() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::PartialFailure {
            failures: vec![],
        }));
        let propagator = Propagator::new(submitter.clone());

        let attestations = vec![create_test_attestation("1000", "1")];
        let result = propagator.propagate_batch(&attestations).await.unwrap();

        assert!(result.is_success());
        assert_eq!(result.total, 1);
        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 0);
    }

    #[tokio::test]
    async fn test_propagate_uses_submitter_correctly() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let propagator = Propagator::new(submitter.clone());

        assert_eq!(submitter.call_count(), 0);

        let attestation = create_test_attestation("1000", "1");
        propagator.propagate(attestation).await.unwrap();

        assert_eq!(submitter.call_count(), 1);

        let attestation = create_test_attestation("1001", "2");
        propagator.propagate(attestation).await.unwrap();

        assert_eq!(submitter.call_count(), 2);
    }
}
