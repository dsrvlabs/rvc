//! Standing CI gate: ARCHITECTURE.md generated region == cargo-metadata generator.
//!
//! On mismatch this test prints a unified-style diff summary and the exact
//! regeneration command so the failure is actionable (not a silent stale pass).

use rvc_architecture_tests::{
    architecture_md_path, assert_generated_agrees_with_policy, extract_generated_body,
    generate_architecture_section, load_workspace_graph, REGENERATE_COMMAND,
};

#[test]
fn architecture_doc_matches_generated_graph() {
    let graph = load_workspace_graph();
    assert_generated_agrees_with_policy(&graph);

    let expected = generate_architecture_section(&graph);
    let path = architecture_md_path();
    let doc =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    let actual = extract_generated_body(&doc).unwrap_or_else(|e| {
        panic!(
            "{e}\n\
             ARCHITECTURE.md must wrap the crate-count + mermaid graph in markers.\n\
             Regenerate with:\n  {REGENERATE_COMMAND}"
        )
    });

    if actual != expected {
        let diff = line_diff_summary(&actual, &expected);
        panic!(
            "ARCHITECTURE.md generated section is stale or was hand-edited.\n\
             \n\
             File: {}\n\
             Regenerate with:\n  {REGENERATE_COMMAND}\n\
             \n\
             --- in-file (actual) vs generator (expected) ---\n\
             {diff}",
            path.display()
        );
    }

    // Crate count in the body must match cargo metadata exactly.
    let n = graph.package_count();
    let bins = graph.binary_count();
    let libs = graph.library_count();
    let count_line =
        format!("modular workspace of {n} crates ({bins} binaries + {libs} libraries)");
    assert!(
        expected.contains(&count_line),
        "generator body missing exact count phrase: {count_line}"
    );
    assert!(
        actual.contains(&count_line),
        "ARCHITECTURE.md missing exact count phrase: {count_line}"
    );

    // REQUIRED_EDGE must appear in the generated mermaid (F109 rot).
    assert!(
        expected.contains("RVC_SIGNER --> RVC_DOPPELGANGER"),
        "generated graph missing required edge rvc-signer → rvc-doppelganger"
    );
}

/// Compact line-oriented diff for panic messages (first mismatches + counts).
fn line_diff_summary(actual: &str, expected: &str) -> String {
    let a: Vec<&str> = actual.lines().collect();
    let e: Vec<&str> = expected.lines().collect();
    let mut out = String::new();
    out.push_str(&format!("actual lines: {}, expected lines: {}\n", a.len(), e.len()));
    let max = a.len().max(e.len());
    let mut shown = 0usize;
    const LIMIT: usize = 40;
    for i in 0..max {
        let al = a.get(i).copied().unwrap_or("<missing>");
        let el = e.get(i).copied().unwrap_or("<missing>");
        if al != el {
            out.push_str(&format!("@@ line {} @@\n- {al}\n+ {el}\n", i + 1));
            shown += 1;
            if shown >= LIMIT {
                out.push_str(&format!("… truncated after {LIMIT} differing lines …\n"));
                break;
            }
        }
    }
    if shown == 0 {
        out.push_str("(no line differences found; check trailing newline / whitespace)\n");
        out.push_str(&format!(
            "actual ends with newline: {}, expected ends with newline: {}\n",
            actual.ends_with('\n'),
            expected.ends_with('\n')
        ));
    }
    out
}
