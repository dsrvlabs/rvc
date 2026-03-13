use std::collections::HashMap;
use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::Span;

use crate::dvt::types::ShareInfo;
use crate::proto::signer::peer_signer_service_server::PeerSignerService;
use crate::proto::signer::{PartialSignRequest, PartialSignResponse};

#[derive(Debug)]
pub struct PeerSignerServiceImpl {
    shares: Arc<HashMap<[u8; 48], ShareInfo>>,
}

impl PeerSignerServiceImpl {
    pub fn new(shares: Arc<HashMap<[u8; 48], ShareInfo>>) -> Self {
        Self { shares }
    }
}

#[tonic::async_trait]
impl PeerSignerService for PeerSignerServiceImpl {
    #[tracing::instrument(
        name = "rvc.signer.dvt.partial_sign",
        skip_all,
        fields(pubkey, share_index)
    )]
    async fn partial_sign(
        &self,
        request: Request<PartialSignRequest>,
    ) -> Result<Response<PartialSignResponse>, Status> {
        let req = request.into_inner();

        if req.signing_root.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "signing_root must be 32 bytes, got {}",
                req.signing_root.len()
            )));
        }

        if req.pubkey.len() != 48 {
            return Err(Status::invalid_argument(format!(
                "pubkey must be 48 bytes, got {}",
                req.pubkey.len()
            )));
        }

        let pubkey: [u8; 48] = req.pubkey.try_into().expect("length already validated");
        let signing_root: [u8; 32] = req.signing_root.try_into().expect("length already validated");

        let pubkey_hex = hex::encode(&pubkey[..6]);
        Span::current().record("pubkey", pubkey_hex.as_str());

        let share =
            self.shares.get(&pubkey).ok_or_else(|| Status::not_found("unknown public key"))?;

        Span::current().record("share_index", share.index);

        // Reconstruct blst SecretKey from share scalar bytes (big-endian)
        let sk = blst::min_pk::SecretKey::from_bytes(&*share.scalar_bytes)
            .map_err(|_| Status::internal("invalid share scalar bytes"))?;

        // Sign the signing root with the share's secret key
        let signature = sk.sign(&signing_root, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[]);
        let sig_bytes = signature.to_bytes();

        Ok(Response::new(PartialSignResponse {
            partial_signature: sig_bytes.to_vec(),
            share_index: share.index,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dvt::types::ShareInfo;
    use zeroize::Zeroizing;

    fn make_share(index: u64) -> ([u8; 48], ShareInfo) {
        let sk = crypto::SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let scalar_bytes = Zeroizing::new(sk.to_bytes());
        let share = ShareInfo { index, threshold: 2, total: 3, scalar_bytes, aggregate_pubkey: pk };
        (pk, share)
    }

    fn make_service(shares: Vec<([u8; 48], ShareInfo)>) -> PeerSignerServiceImpl {
        let map: HashMap<[u8; 48], ShareInfo> = shares.into_iter().collect();
        PeerSignerServiceImpl::new(Arc::new(map))
    }

    #[tokio::test]
    async fn test_partial_sign_valid_request() {
        let (pk, share) = make_share(1);
        let svc = make_service(vec![(pk, share)]);

        let req = Request::new(PartialSignRequest {
            signing_root: vec![0xAB; 32],
            pubkey: pk.to_vec(),
            requester_index: 2,
        });

        let resp = svc.partial_sign(req).await.unwrap();
        let inner = resp.into_inner();
        assert_eq!(inner.partial_signature.len(), 96);
        assert_eq!(inner.share_index, 1);
    }

    #[tokio::test]
    async fn test_partial_sign_unknown_pubkey_returns_not_found() {
        let (pk, share) = make_share(1);
        let svc = make_service(vec![(pk, share)]);

        let req = Request::new(PartialSignRequest {
            signing_root: vec![0xAB; 32],
            pubkey: vec![0xFF; 48],
            requester_index: 2,
        });

        let err = svc.partial_sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn test_partial_sign_invalid_signing_root_length() {
        let svc = make_service(vec![]);

        let req = Request::new(PartialSignRequest {
            signing_root: vec![0u8; 16],
            pubkey: vec![0u8; 48],
            requester_index: 0,
        });

        let err = svc.partial_sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("signing_root"));
    }

    #[tokio::test]
    async fn test_partial_sign_invalid_pubkey_length() {
        let svc = make_service(vec![]);

        let req = Request::new(PartialSignRequest {
            signing_root: vec![0u8; 32],
            pubkey: vec![0u8; 32],
            requester_index: 0,
        });

        let err = svc.partial_sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("pubkey"));
    }

    #[tokio::test]
    async fn test_partial_sign_empty_fields() {
        let svc = make_service(vec![]);

        let req = Request::new(PartialSignRequest {
            signing_root: vec![],
            pubkey: vec![],
            requester_index: 0,
        });

        let err = svc.partial_sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_partial_sign_deterministic() {
        let (pk, share) = make_share(1);
        let svc = make_service(vec![(pk, share)]);
        let signing_root = vec![0xCD; 32];

        let req1 = Request::new(PartialSignRequest {
            signing_root: signing_root.clone(),
            pubkey: pk.to_vec(),
            requester_index: 2,
        });
        let resp1 = svc.partial_sign(req1).await.unwrap().into_inner();

        let req2 = Request::new(PartialSignRequest {
            signing_root: signing_root.clone(),
            pubkey: pk.to_vec(),
            requester_index: 3,
        });
        let resp2 = svc.partial_sign(req2).await.unwrap().into_inner();

        // Same signing root + same share → same partial signature
        assert_eq!(resp1.partial_signature, resp2.partial_signature);
        assert_eq!(resp1.share_index, resp2.share_index);
    }

    #[tokio::test]
    async fn test_partial_sign_different_roots_differ() {
        let (pk, share) = make_share(1);
        let svc = make_service(vec![(pk, share)]);

        let req1 = Request::new(PartialSignRequest {
            signing_root: vec![0x01; 32],
            pubkey: pk.to_vec(),
            requester_index: 0,
        });
        let resp1 = svc.partial_sign(req1).await.unwrap().into_inner();

        let req2 = Request::new(PartialSignRequest {
            signing_root: vec![0x02; 32],
            pubkey: pk.to_vec(),
            requester_index: 0,
        });
        let resp2 = svc.partial_sign(req2).await.unwrap().into_inner();

        assert_ne!(resp1.partial_signature, resp2.partial_signature);
    }

    #[tokio::test]
    async fn test_multiple_shares() {
        let (pk1, share1) = make_share(1);
        let (pk2, share2) = make_share(2);
        let svc = make_service(vec![(pk1, share1), (pk2, share2)]);

        let req1 = Request::new(PartialSignRequest {
            signing_root: vec![0xAA; 32],
            pubkey: pk1.to_vec(),
            requester_index: 0,
        });
        let resp1 = svc.partial_sign(req1).await.unwrap().into_inner();
        assert_eq!(resp1.share_index, 1);

        let req2 = Request::new(PartialSignRequest {
            signing_root: vec![0xAA; 32],
            pubkey: pk2.to_vec(),
            requester_index: 0,
        });
        let resp2 = svc.partial_sign(req2).await.unwrap().into_inner();
        assert_eq!(resp2.share_index, 2);
    }

    /// 3-node in-process peer coordination test.
    ///
    /// Spins up 3 PeerSignerService gRPC servers, each holding one share
    /// of the same aggregate key. A client then connects to each peer and
    /// requests partial signatures, verifying that all 3 return valid responses.
    #[tokio::test]
    async fn test_three_node_in_process_peer_coordination() {
        use crate::proto::signer::peer_signer_service_client::PeerSignerServiceClient;
        use crate::PeerSignerServiceServer;
        use tokio::net::TcpListener;

        // Generate 3 independent share keys (each node has its own share)
        // In a real DVT setup these would be Shamir shares; here we just
        // verify the gRPC plumbing works end-to-end with 3 nodes.
        let aggregate_pubkey = {
            let sk = crypto::SecretKey::generate();
            sk.public_key().to_bytes()
        };

        let mut services = Vec::new();
        let mut listeners = Vec::new();

        for index in 1..=3u64 {
            let sk = crypto::SecretKey::generate();
            let scalar_bytes = Zeroizing::new(sk.to_bytes());
            let share = ShareInfo { index, threshold: 2, total: 3, scalar_bytes, aggregate_pubkey };

            let mut map = HashMap::new();
            map.insert(aggregate_pubkey, share);
            let svc = PeerSignerServiceImpl::new(Arc::new(map));

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            listeners.push(addr);
            services.push((svc, listener));
        }

        // Spawn 3 gRPC servers
        for (svc, listener) in services {
            tokio::spawn(async move {
                let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                tonic::transport::Server::builder()
                    .add_service(PeerSignerServiceServer::new(svc))
                    .serve_with_incoming(incoming)
                    .await
                    .unwrap();
            });
        }

        // Give servers a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect a client to each server and request partials
        let signing_root = [0xAB; 32];
        let mut collected = Vec::new();

        for addr in &listeners {
            let uri = format!("http://{}", addr);
            let mut client = PeerSignerServiceClient::connect(uri).await.unwrap();

            let req = PartialSignRequest {
                signing_root: signing_root.to_vec(),
                pubkey: aggregate_pubkey.to_vec(),
                requester_index: 0,
            };

            let resp = client.partial_sign(req).await.unwrap().into_inner();
            assert_eq!(resp.partial_signature.len(), 96);
            assert!((1..=3).contains(&resp.share_index));
            collected.push((resp.share_index, resp.partial_signature));
        }

        // Verify we got 3 distinct partial signatures from 3 different shares
        assert_eq!(collected.len(), 3);
        let indices: std::collections::HashSet<u64> =
            collected.iter().map(|(idx, _)| *idx).collect();
        assert_eq!(indices.len(), 3, "all 3 share indices should be distinct");

        // Verify all partials are different (different keys → different sigs)
        let sigs: std::collections::HashSet<Vec<u8>> =
            collected.iter().map(|(_, sig)| sig.clone()).collect();
        assert_eq!(sigs.len(), 3, "all 3 partial signatures should be distinct");
    }
}
