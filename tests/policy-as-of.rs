use std::path;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn sha1_signature() {
    // Create an empty policy configuration file.  We use this
    // instead of the system-wide policy configuration file,
    // which might be more strict than what our test vectors
    // expect.
    let policy = path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("empty-policy.toml");
    std::fs::write(&policy, "").unwrap();

    Command::cargo_bin("sqv").expect("have sqv")
        .env("SEQUOIA_CRYPTO_POLICY", &policy)
        .current_dir(path::Path::new("tests").join("data"))
        .args(&["--keyring",
                "mrpast.key",
                "a-cypherpunks-manifesto.txt.sha1.sig",
                "a-cypherpunks-manifesto.txt"])
        .assert()
        .failure();

    Command::cargo_bin("sqv").expect("have sqv")
        .env("SEQUOIA_CRYPTO_POLICY", &policy)
        .current_dir(path::Path::new("tests").join("data"))
        .args(&["--keyring",
                "mrpast.key",
                "--policy-as-of", "2008-08-03",
                "a-cypherpunks-manifesto.txt.sha1.sig",
                "a-cypherpunks-manifesto.txt"])
        .assert()
        .success()
        .stdout(predicate::eq(
            b"40A0E8E64DCC61D977DD86D7165F9B3B60351FBC\n" as &[u8]));
}
