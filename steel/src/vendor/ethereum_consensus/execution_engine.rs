use crate::ethereum_consensus::{
    error::{Error, ExecutionEngineError},
    state_transition::Result,
};

/// `PayloadRequest` abstracts over the data sent to the `ExecutionEngine`.
/// NOTE: just a "marker" trait for now, until we have more substantial support for execution.
pub trait PayloadRequest {}

/// `ExecutionEngine` abstracts over the interface between consensus and execution client.
pub trait ExecutionEngine {
    /// Verify the new payload and associated data contained in `new_payload_request`.
    /// Either return `Err` describing a failure or `Ok(())` if validation succeeds.
    fn verify_and_notify_new_payload(
        &self,
        new_payload_request: &impl PayloadRequest,
    ) -> Result<()>;
}

/// A "no-op" implementation that succeeds for `true` or fails for `false`.
/// Useful for mocking the execution engine behavior.
impl ExecutionEngine for bool {
    fn verify_and_notify_new_payload(&self, _: &impl PayloadRequest) -> Result<()> {
        self.then_some(())
            .ok_or(Error::ExecutionEngine(ExecutionEngineError::InvalidPayload))
    }
}
