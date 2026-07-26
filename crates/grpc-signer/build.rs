use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().join("proto");

    // Compile v2 proto only (RF2-15: v1 retired from this crate).
    // bin/rvc-signer still compiles signer.proto for its own v1 stubs until RF2-17.
    let proto_v2 = proto_root.join("signer.v2.proto");
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto_v2], &[&proto_root])?;

    Ok(())
}
