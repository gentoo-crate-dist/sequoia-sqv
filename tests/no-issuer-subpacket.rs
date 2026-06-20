#[cfg(test)]
mod integration {
    use std::path;

    use assert_cmd::Command;
    use predicates::prelude::*;

    #[test]
    fn no_issuer_subpacket() {
        Command::cargo_bin("sqv").expect("have sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .args(&["--keyring", "bad-subkey-keyring.pgp",
                    "no-issuer-subpacket.sig", "bad-subkey.txt"])
            .assert()
            .failure()
            .stderr(predicate::eq(
                b"Missing key <unknown issuer>, which is needed to verify signature.\n" as &[u8]));
    }
}
