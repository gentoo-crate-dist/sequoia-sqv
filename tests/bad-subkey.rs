#[cfg(test)]
mod integration {
    use std::path;

    use assert_cmd::Command;
    use predicates::prelude::*;

    #[test]
    fn bad_subkey() {
        Command::cargo_bin("sqv").expect("have sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .args(&["--keyring", "bad-subkey-keyring.pgp",
                    "bad-subkey.txt.sig", "bad-subkey.txt"])
            .assert()
            .success()
            .stdout(predicate::eq(
                b"8F17777118A33DDA9BA48E62AACB3243630052D9\n" as &[u8]));
    }
}
