#[cfg(test)]
mod integration {
    use std::path;

    use assert_cmd::Command;

    #[test]
    fn no_issuer_subpacket() {
        Command::cargo_bin("sqv").expect("have sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .args(&["--keyring", "keybox.kbx",
                    "bad-subkey.txt.sig", "bad-subkey.txt"])
            .assert()
            .failure()
            .stderr(predicates::function::function(|data| {
                let data = String::from_utf8_lossy(data);
                data.contains("File appears to be in keybox format, which is not supported")
            }));
    }
}
