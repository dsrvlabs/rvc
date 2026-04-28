//! Response-size caps for BN-facing HTTP requests (A9 / H-12).
//!
//! `ResponseCaps` holds configurable ceilings for JSON body and SSE event
//! sizes.  `read_body_capped` streams the response body in chunks, counting
//! bytes, and returns `BeaconError::BodyTooLarge` before allocating more than
//! the configured cap.

use bytes::Bytes;

use crate::BeaconError;

/// Per-response size limits for BN-facing HTTP traffic.
#[derive(Clone, Copy, Debug)]
pub struct ResponseCaps {
    /// Maximum bytes allowed in a JSON response body (default 32 MiB).
    pub max_body_bytes: usize,
    /// Maximum bytes allowed in a single SSE event (default 64 KiB).
    pub max_sse_event_bytes: usize,
}

impl ResponseCaps {
    /// Default maximum JSON response body (32 MiB).
    pub const DEFAULT_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
    /// Default maximum SSE event payload (64 KiB).
    pub const DEFAULT_MAX_SSE_EVENT_BYTES: usize = 64 * 1024;
}

impl Default for ResponseCaps {
    fn default() -> Self {
        Self {
            max_body_bytes: Self::DEFAULT_MAX_BODY_BYTES,
            max_sse_event_bytes: Self::DEFAULT_MAX_SSE_EVENT_BYTES,
        }
    }
}

/// Read a response body up to `cap` bytes, streaming in chunks.
///
/// Rejects *before* any allocation when `Content-Length` header exceeds `cap`.
/// Otherwise streams chunks and returns `BeaconError::BodyTooLarge` as soon as
/// the running total would exceed `cap`.
pub(crate) async fn read_body_capped(
    response: reqwest::Response,
    cap: usize,
) -> Result<Bytes, BeaconError> {
    // Fast-reject: Content-Length header advertises too much data.
    if let Some(content_length) = response.content_length() {
        let cl = content_length as usize;
        if cl > cap {
            return Err(BeaconError::BodyTooLarge { expected: cap, got_so_far: cl });
        }
    }

    // Stream body in chunks, counting bytes.
    let mut body: Vec<u8> = Vec::new();
    let mut response = response;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let new_total = body.len() + chunk.len();
                if new_total > cap {
                    return Err(BeaconError::BodyTooLarge { expected: cap, got_so_far: new_total });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                return Err(BeaconError::ParseError(format!(
                    "failed to read response body chunk: {e}"
                )))
            }
        }
    }
    Ok(Bytes::from(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_caps_values() {
        let caps = ResponseCaps::default();
        assert_eq!(caps.max_body_bytes, 32 * 1024 * 1024);
        assert_eq!(caps.max_sse_event_bytes, 64 * 1024);
    }

    #[test]
    fn test_response_caps_is_copy() {
        let caps = ResponseCaps::default();
        let _copy = caps; // Copy trait
        let _ = caps.max_body_bytes; // original still accessible
    }

    #[test]
    fn test_response_caps_debug() {
        let caps = ResponseCaps { max_body_bytes: 1024, max_sse_event_bytes: 512 };
        let s = format!("{caps:?}");
        assert!(s.contains("1024"));
        assert!(s.contains("512"));
    }
}
