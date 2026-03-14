use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tonic::transport::{Channel, Endpoint};
use tracing::warn;

use crate::backend::dvt::{PeerRequestError, PeerRequester};
use crate::proto::signer::peer_signer_service_client::PeerSignerServiceClient;
use crate::proto::signer::PartialSignRequest;
use crate::tls::TlsConfig;

#[derive(Error, Debug)]
pub enum PeerClientError {
    #[error("failed to connect to peer {addr}: {source}")]
    Connect { addr: String, source: tonic::transport::Error },

    #[error("failed to build TLS config: {0}")]
    Tls(String),

    #[error("peer {addr} RPC failed: {source}")]
    Rpc { addr: String, source: tonic::Status },

    #[error("peer {addr} timed out after {timeout:?}")]
    Timeout { addr: String, timeout: Duration },

    #[error("peer not found: {0}")]
    PeerNotFound(String),
}

/// gRPC-based peer requester that connects to DVT peers.
pub struct GrpcPeerRequester {
    peers: Vec<(String, PeerSignerServiceClient<Channel>)>,
    timeout: Duration,
}

impl GrpcPeerRequester {
    /// Connect to a list of peer addresses.
    ///
    /// If `tls_config` is provided, mTLS is used for all connections.
    pub async fn connect(
        peers: &[String],
        tls_config: Option<&TlsConfig>,
        timeout: Duration,
    ) -> Result<Self, PeerClientError> {
        let client_tls = match tls_config {
            Some(tls) => {
                Some(tls.to_client_tls_config().map_err(|e| PeerClientError::Tls(e.to_string()))?)
            }
            None => None,
        };

        let mut connected = Vec::with_capacity(peers.len());

        for addr in peers {
            let scheme = if client_tls.is_some() { "https" } else { "http" };
            let uri = format!("{}://{}", scheme, addr);
            let mut endpoint = Endpoint::from_shared(uri)
                .map_err(|e| PeerClientError::Connect { addr: addr.clone(), source: e })?
                .timeout(timeout);

            if let Some(ref tls) = client_tls {
                endpoint = endpoint
                    .tls_config(tls.clone())
                    .map_err(|e| PeerClientError::Connect { addr: addr.clone(), source: e })?;
            }

            let channel = endpoint
                .connect()
                .await
                .map_err(|e| PeerClientError::Connect { addr: addr.clone(), source: e })?;

            connected.push((addr.clone(), PeerSignerServiceClient::new(channel)));
        }

        Ok(Self { peers: connected, timeout })
    }

    /// Return the list of connected peer addresses.
    pub fn peer_addrs(&self) -> Vec<&str> {
        self.peers
            .iter()
            .map(|(addr, _client): &(String, PeerSignerServiceClient<Channel>)| addr.as_str())
            .collect()
    }

    /// Request partial signatures from all connected peers concurrently.
    ///
    /// Returns a vector of `(share_index, partial_signature)` for successful responses.
    /// Peers that fail or timeout are logged and skipped.
    pub async fn request_all_partials(
        &self,
        signing_root: &[u8; 32],
        pubkey: &[u8; 48],
        requester_index: u64,
    ) -> Vec<(u64, [u8; 96])> {
        let mut handles = tokio::task::JoinSet::new();

        for (addr, client) in &self.peers {
            let addr: String = addr.clone();
            let mut client: PeerSignerServiceClient<Channel> = client.clone();
            let signing_root = signing_root.to_vec();
            let pubkey = pubkey.to_vec();
            let timeout = self.timeout;

            handles.spawn(async move {
                let req = PartialSignRequest { signing_root, pubkey, requester_index };

                let result: Result<
                    tonic::Response<crate::proto::signer::PartialSignResponse>,
                    tonic::Status,
                > = match tokio::time::timeout(timeout, client.partial_sign(req)).await {
                    Ok(r) => r,
                    Err(_) => return Err(PeerClientError::Timeout { addr, timeout }),
                };

                match result {
                    Ok(resp) => {
                        let inner = resp.into_inner();
                        let sig: [u8; 96] = inner.partial_signature.try_into().map_err(|_| {
                            PeerClientError::Rpc {
                                addr: addr.clone(),
                                source: tonic::Status::internal("invalid signature length"),
                            }
                        })?;
                        Ok((addr, inner.share_index, sig))
                    }
                    Err(status) => Err(PeerClientError::Rpc { addr, source: status }),
                }
            });
        }

        let mut results = Vec::new();
        while let Some(join_result) = handles.join_next().await {
            match join_result {
                Ok(Ok((_addr, share_index, sig))) => {
                    results.push((share_index, sig));
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "peer partial sign request failed");
                }
                Err(e) => {
                    warn!(error = %e, "peer task panicked");
                }
            }
        }

        results
    }
}

#[async_trait]
impl PeerRequester for GrpcPeerRequester {
    async fn request_partial(
        &self,
        peer_addr: &str,
        signing_root: &[u8; 32],
        pubkey: &[u8; 48],
    ) -> Result<(u64, [u8; 96]), PeerRequestError> {
        let (_, client) =
            self.peers.iter().find(|(addr, _)| addr == peer_addr).ok_or_else(|| {
                PeerRequestError::RequestFailed(format!("peer not found: {}", peer_addr))
            })?;

        let mut client = client.clone();
        let req = PartialSignRequest {
            signing_root: signing_root.to_vec(),
            pubkey: pubkey.to_vec(),
            requester_index: 0,
        };

        let result = tokio::time::timeout(self.timeout, client.partial_sign(req))
            .await
            .map_err(|_| PeerRequestError::Timeout)?
            .map_err(|e| PeerRequestError::RequestFailed(format!("RPC failed: {}", e)))?;

        let inner = result.into_inner();
        let sig: [u8; 96] = inner.partial_signature.try_into().map_err(|_| {
            PeerRequestError::RequestFailed("invalid signature length from peer".to_string())
        })?;

        Ok((inner.share_index, sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_client_error_display_timeout() {
        let err = PeerClientError::Timeout {
            addr: "127.0.0.1:50053".to_string(),
            timeout: Duration::from_millis(2000),
        };
        let msg = err.to_string();
        assert!(msg.contains("127.0.0.1:50053"));
        assert!(msg.contains("timed out"));
    }

    #[test]
    fn test_peer_client_error_display_tls() {
        let err = PeerClientError::Tls("bad cert".to_string());
        assert!(err.to_string().contains("TLS"));
    }

    #[test]
    fn test_peer_client_error_display_rpc() {
        let err = PeerClientError::Rpc {
            addr: "peer1:50053".to_string(),
            source: tonic::Status::not_found("key missing"),
        };
        let msg = err.to_string();
        assert!(msg.contains("peer1:50053"));
        assert!(msg.contains("RPC failed"));
    }

    #[test]
    fn test_peer_client_error_display_not_found() {
        let err = PeerClientError::PeerNotFound("unknown:1234".to_string());
        assert!(err.to_string().contains("unknown:1234"));
    }
}
