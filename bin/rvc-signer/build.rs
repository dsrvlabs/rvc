use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().join("proto");

    // Compile v2 proto only (RF2-17: v1 signer.proto retired workspace-wide).
    let proto_v2 = proto_root.join("signer.v2.proto");

    let build_client = cfg!(feature = "dvt");

    tonic_build::configure()
        .build_server(true)
        .build_client(build_client)
        .compile_protos(&[proto_v2], &[&proto_root])?;

    Ok(())
}
