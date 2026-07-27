/// CI symbol-grep guard (CQ-3.2, architecture.md §4 row C3).
///
/// Asserts that the symbol `propose_block_unvalidated` does not appear anywhere
/// in `crates/block-service/src/service/`.  If it does, the deleted unvalidated
/// entry-point has been reintroduced and this test fails loudly.
#[test]
fn test_no_propose_block_unvalidated_symbol_in_service_rs() {
    let service_src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/service/mod.rs"))
            .expect("could not read crates/block-service/src/service/mod.rs");

    assert!(
        !service_src.contains("propose_block_unvalidated"),
        "symbol `propose_block_unvalidated` found in service/mod.rs — \
         the unvalidated propose_block entry-point must not be reintroduced (CQ-3.2 / C3)"
    );
}

/// F101: `propose_block_with_mode` must not be crate-public — it skips the
/// response validation that `propose_block` performs.
#[test]
fn test_propose_block_with_mode_not_publicly_reachable() {
    let service_src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/service/mod.rs"))
            .expect("could not read crates/block-service/src/service/mod.rs");

    assert!(
        !service_src.contains("pub async fn propose_block_with_mode"),
        "propose_block_with_mode must not be `pub` (external crates would bypass validation)"
    );
    assert!(
        service_src.contains("pub(crate) async fn propose_block_with_mode"),
        "propose_block_with_mode must remain `pub(crate)` for in-crate tests"
    );
}
