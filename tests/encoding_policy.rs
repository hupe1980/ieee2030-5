// exi/SR-001
#[test]
fn documents_unsupported_server_encoding() {
    let policy = include_str!("../site/content/guides/encodings.md");
    assert!(
        policy
            .lines()
            .any(|row| row == "| `application/sep-exi` | Unsupported |")
    );
    assert!(policy.contains("GEN.050"));
    assert!(policy.contains("GEN.051"));
    assert!(policy.contains("cannot currently meet GEN.050"));
}
