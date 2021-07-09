use assert_cmd::Command;
use std::path;

/// Asserts that duplicate signatures are properly ignored.
#[test]
fn ignore_duplicates() {
    // Duplicate is ignored, but remaining one is ok.
    Command::cargo_bin("sqv")
        .unwrap()
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "a-cypherpunks-manifesto.txt.ed25519.sig.duplicated",
            "a-cypherpunks-manifesto.txt",
        ])
        .assert()
        .success()
        .stdout(b"8E8C33FA4626337976D97978069C0C348DD82C19\n".as_ref());

    // Duplicate is ignored, and fails to meet the threshold.
    Command::cargo_bin("sqv")
        .unwrap()
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "--signatures=2",
            "a-cypherpunks-manifesto.txt.ed25519.sig.duplicated",
            "a-cypherpunks-manifesto.txt",
        ])
        .assert()
        .failure()
        .stdout(b"8E8C33FA4626337976D97978069C0C348DD82C19\n".as_ref());
}
