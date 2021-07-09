use assert_cmd::Command;
use std::path;

/// Asserts that multiple signatures from the same Cert are properly
/// ignored.
#[test]
fn ignore_multiple_signatures() {
    // Multiple signatures from the same Cert are ignored, and fails to
    // meet the threshold.
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
