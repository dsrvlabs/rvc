use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, warn};

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

/// Per-peer connection parameters for DVT gRPC connections.
///
/// Carries the TCP address **and** the TLS SNI hostname to pin.
///
/// # SNI pinning (ISSUE-4.1 / L-1 fix)
///
/// `sni_cn` is set as `domain_name` on the per-peer `ClientTlsConfig` clone
/// before dialling.  rustls then refuses any server certificate that is not
/// valid for `sni_cn`, preventing a certificate issued for peer-A from being
/// silently accepted when the client intended to connect to peer-B.
///
/// When TLS is disabled (insecure mode) `sni_cn` is ignored.
#[derive(Debug, Clone)]
pub struct PeerConnectInfo {
    /// TCP address of the peer (e.g. `"peer-a.cluster.local:50051"`).
    pub addr: String,
    /// Expected TLS SNI hostname — the peer's `peer_cn` from the allow-list.
    ///
    /// Must be a valid DNS name accepted by rustls `ServerName` (e.g.
    /// `"peer-a.cluster.local"`).  Leave empty when TLS is disabled or when
    /// SNI pinning should be skipped for a peer (a warning is logged).
    pub sni_cn: String,
}

/// gRPC-based peer requester that connects to DVT peers.
pub struct GrpcPeerRequester {
    peers: Vec<(String, PeerSignerServiceClient<Channel>)>,
    timeout: Duration,
}

impl GrpcPeerRequester {
    /// Connect to a list of peers, pinning SNI per peer.
    ///
    /// If `tls_config` is provided, mTLS is used.  For each peer, the
    /// `domain_name` on the `ClientTlsConfig` is set to `peer.sni_cn` before
    /// dialling, so rustls verifies the server certificate against the
    /// peer-specific hostname.
    ///
    /// # SNI pinning (ISSUE-4.1 / L-1 fix)
    ///
    /// Without this pinning, any certificate valid under the shared CA would
    /// be accepted regardless of which peer it was issued to.  By setting
    /// `domain_name(sni_cn)` per peer, rustls refuses certificates that are
    /// not issued for the expected peer hostname.
    ///
    /// If `peer.sni_cn` is empty and TLS is active, pinning is skipped for
    /// that peer and a warning is logged.  Operators should add an `addr`
    /// field to the corresponding `[[peer]]` entry in `dvt-allowed-peers.toml`
    /// to enable SNI pinning.
    pub async fn connect(
        peers: &[PeerConnectInfo],
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

        for peer in peers {
            let scheme = if client_tls.is_some() { "https" } else { "http" };
            let uri = format!("{}://{}", scheme, peer.addr);
            let mut endpoint = Endpoint::from_shared(uri)
                .map_err(|e| PeerClientError::Connect { addr: peer.addr.clone(), source: e })?
                .timeout(timeout);

            if let Some(ref tls) = client_tls {
                // L-1 SNI pinning: set domain_name per peer so rustls verifies
                // the server certificate is issued for this specific peer's
                // expected hostname.  Without this, any cert valid under the
                // shared CA passes for any peer — a silent impersonation path.
                let pinned_tls = if peer.sni_cn.is_empty() {
                    warn!(
                        addr = %peer.addr,
                        "DVT peer has no SNI configured; TLS cert hostname will not be pinned. \
                         Add 'addr' to the [[peer]] entry in dvt-allowed-peers.toml to enable \
                         per-peer SNI pinning (ISSUE-4.1 / L-1)."
                    );
                    tls.clone()
                } else {
                    debug!(addr = %peer.addr, sni = %peer.sni_cn, "SNI pinned for DVT peer");
                    tls.clone().domain_name(&peer.sni_cn)
                };
                endpoint = endpoint
                    .tls_config(pinned_tls)
                    .map_err(|e| PeerClientError::Connect { addr: peer.addr.clone(), source: e })?;
            }

            let channel = endpoint
                .connect()
                .await
                .map_err(|e| PeerClientError::Connect { addr: peer.addr.clone(), source: e })?;

            connected.push((peer.addr.clone(), PeerSignerServiceClient::new(channel)));
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
