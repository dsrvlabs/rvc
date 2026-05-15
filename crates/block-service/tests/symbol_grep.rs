/// CI symbol-grep guard (CQ-3.2, architecture.md §4 row C3).
///
/// Asserts that the symbol `propose_block_unvalidated` does not appear anywhere
/// in `crates/block-service/src/service.rs`.  If it does, the deleted unvalidated
/// entry-point has been reintroduced and this test fails loudly.
#[test]
fn test_no_propose_block_unvalidated_symbol_in_service_rs() {
    let service_src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/service.rs"))
            .expect("could not read crates/block-service/src/service.rs");

    assert!(
        !service_src.contains("propose_block_unvalidated"),
        "symbol `propose_block_unvalidated` found in service.rs — \
         the unvalidated propose_block entry-point must not be reintroduced (CQ-3.2 / C3)"
    );
}
