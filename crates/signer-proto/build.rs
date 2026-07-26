use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().join("proto");

    // Sole workspace compilation of signer.v2.proto (RF3-14).
    // Unrelated protos keep their own build scripts (see crates/rvc).
    let proto_v2 = proto_root.join("signer.v2.proto");

    tonic_build::configure()
        .build_server(cfg!(feature = "server"))
        .build_client(cfg!(feature = "client"))
        .compile_protos(&[proto_v2], &[&proto_root])?;

    Ok(())
}
