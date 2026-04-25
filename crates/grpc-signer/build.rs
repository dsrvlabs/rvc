use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().join("proto");

    // Keep v1 proto for ListPublicKeys/GetStatus used during connect (ISSUE-1.8)
    // NOTE: proto/signer.proto deletion is deferred to ISSUE-1.9 because the v1
    // proto is still re-exported by `crates/grpc-signer` for the ListPublicKeys
    // call in GrpcRemoteSigner::connect.  After ISSUE-1.9 switches the connect
    // path to the v2 ListPublicKeys RPC, the v1 file and these lines can be
    // deleted.
    let proto_v1 = proto_root.join("signer.proto");
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto_v1], &[&proto_root])?;

    // Compile v2 proto
    let proto_v2 = proto_root.join("signer.v2.proto");
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto_v2], &[&proto_root])?;

    Ok(())
}
