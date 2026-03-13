pub mod proto {
    pub mod signer {
        tonic::include_proto!("signer");
    }
}

pub use proto::signer::signer_service_server::{SignerService, SignerServiceServer};
pub use proto::signer::{
    GetStatusRequest, GetStatusResponse, ListPublicKeysRequest, ListPublicKeysResponse,
    SignRequest, SignResponse,
};

fn main() {
    println!("rvc-signer: not yet implemented");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_request_fields() {
        let req = SignRequest { signing_root: vec![0u8; 32], pubkey: vec![0u8; 48] };
        assert_eq!(req.signing_root.len(), 32);
        assert_eq!(req.pubkey.len(), 48);
    }

    #[test]
    fn test_sign_response_fields() {
        let resp = SignResponse { signature: vec![0u8; 96] };
        assert_eq!(resp.signature.len(), 96);
    }

    #[test]
    fn test_list_public_keys_response() {
        let resp = ListPublicKeysResponse { pubkeys: vec![vec![1u8; 48], vec![2u8; 48]] };
        assert_eq!(resp.pubkeys.len(), 2);
    }

    #[test]
    fn test_get_status_response() {
        let resp = GetStatusResponse { ready: true, backend: "basic".to_string(), key_count: 5 };
        assert!(resp.ready);
        assert_eq!(resp.backend, "basic");
        assert_eq!(resp.key_count, 5);
    }
}
