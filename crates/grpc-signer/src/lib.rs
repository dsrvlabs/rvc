pub mod client;
pub mod proto {
    pub mod signer {
        tonic::include_proto!("signer");
    }
}

pub use client::{GrpcRemoteSigner, GrpcRemoteSignerConfig};
pub use proto::signer::peer_signer_service_client::PeerSignerServiceClient;
pub use proto::signer::signer_service_client::SignerServiceClient;
pub use proto::signer::signer_service_server::{SignerService, SignerServiceServer};
pub use proto::signer::{
    GetStatusRequest, GetStatusResponse, ListPublicKeysRequest, ListPublicKeysResponse,
    PartialSignRequest, PartialSignResponse, SignRequest, SignResponse,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_types_accessible() {
        let req = SignRequest { signing_root: vec![0u8; 32], pubkey: vec![0u8; 48] };
        assert_eq!(req.signing_root.len(), 32);
        assert_eq!(req.pubkey.len(), 48);
    }

    #[test]
    fn test_list_public_keys_request_default() {
        let req = ListPublicKeysRequest {};
        let _ = req;
    }

    #[test]
    fn test_get_status_request_default() {
        let req = GetStatusRequest {};
        let _ = req;
    }

    #[test]
    fn test_get_status_response_fields() {
        let resp = GetStatusResponse { ready: false, backend: "remote".to_string(), key_count: 0 };
        assert!(!resp.ready);
        assert_eq!(resp.backend, "remote");
        assert_eq!(resp.key_count, 0);
    }

    #[test]
    fn test_partial_sign_request_fields() {
        let req = PartialSignRequest {
            signing_root: vec![0u8; 32],
            pubkey: vec![0u8; 48],
            requester_index: 5,
        };
        assert_eq!(req.signing_root.len(), 32);
        assert_eq!(req.pubkey.len(), 48);
        assert_eq!(req.requester_index, 5);
    }

    #[test]
    fn test_partial_sign_response_fields() {
        let resp = PartialSignResponse { partial_signature: vec![0u8; 96], share_index: 2 };
        assert_eq!(resp.partial_signature.len(), 96);
        assert_eq!(resp.share_index, 2);
    }
}
