use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().join("proto");

    let proto_v1 = proto_root.join("signer.proto");
    let proto_v2 = proto_root.join("signer.v2.proto");

    let build_client = cfg!(feature = "dvt");

    // Compile v1 proto (kept until ISSUE-1.8 migration is complete)
    tonic_build::configure()
        .build_server(true)
        .build_client(build_client)
        .compile_protos(&[proto_v1], &[&proto_root])?;

    // Compile v2 proto
    tonic_build::configure()
        .build_server(true)
        .build_client(build_client)
        .compile_protos(&[proto_v2], &[&proto_root])?;

    Ok(())
}
