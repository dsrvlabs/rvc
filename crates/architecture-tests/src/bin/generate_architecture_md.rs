//! Regenerate the `<!-- BEGIN GENERATED -->` … `<!-- END GENERATED -->` section
//! of workspace-root `ARCHITECTURE.md` from `cargo metadata`.
//!
//! ```text
//! cargo run -p rvc-architecture-tests --bin generate-architecture-md
//! make architecture-doc
//! ```

fn main() {
    match rvc_architecture_tests::regenerate_architecture_md() {
        Ok(true) => {
            println!("Updated {}", rvc_architecture_tests::architecture_md_path().display());
        }
        Ok(false) => {
            println!(
                "Already up to date: {}",
                rvc_architecture_tests::architecture_md_path().display()
            );
        }
        Err(e) => {
            eprintln!("generate-architecture-md failed: {e}");
            std::process::exit(1);
        }
    }
}
