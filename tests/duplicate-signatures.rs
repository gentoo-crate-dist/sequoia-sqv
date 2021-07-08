use assert_cli::Assert;
use std::path;

/// Asserts that duplicate signatures are properly ignored.
#[test]
fn ignore_duplicates() {
    // Duplicate is ignored, but remaining one is ok.
    Assert::cargo_binary("sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .with_args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "a-cypherpunks-manifesto.txt.ed25519.sig.duplicated",
            "a-cypherpunks-manifesto.txt",
        ])
        .unwrap();

    // Duplicate is ignored, and fails to meet the threshold.
    Assert::cargo_binary("sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .with_args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "--signatures=2",
            "a-cypherpunks-manifesto.txt.ed25519.sig.duplicated",
            "a-cypherpunks-manifesto.txt",
        ])
        .fails()
        .unwrap();
}
