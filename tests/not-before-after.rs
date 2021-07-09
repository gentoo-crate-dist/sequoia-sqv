#[cfg(test)]
mod integration {
    use assert_cmd::Command;
    use std::path;

    #[test]
    fn unconstrained() {
        Command::cargo_bin("sqv")
            .unwrap()
            .current_dir(path::Path::new("tests").join("data"))
            .args(&[
                "--keyring",
                "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
                "a-cypherpunks-manifesto.txt.ed25519.sig",
                "a-cypherpunks-manifesto.txt",
            ])
            .assert()
            .success()
            .stdout(b"8E8C33FA4626337976D97978069C0C348DD82C19\n".as_ref());
    }

    #[test]
    fn in_interval() {
        Command::cargo_bin("sqv")
            .unwrap()
            .current_dir(path::Path::new("tests").join("data"))
            .args(&[
                "--keyring",
                "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
                "--not-before",
                "2018-08-14",
                "--not-after",
                "2018-08-15",
                "a-cypherpunks-manifesto.txt.ed25519.sig",
                "a-cypherpunks-manifesto.txt",
            ])
            .assert()
            .success()
            .stdout(b"8E8C33FA4626337976D97978069C0C348DD82C19\n".as_ref());
    }

    #[test]
    fn before() {
        Command::cargo_bin("sqv")
            .unwrap()
            .current_dir(path::Path::new("tests").join("data"))
            .args(&[
                "--keyring",
                "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
                "--not-before",
                "2018-08-15",
                "a-cypherpunks-manifesto.txt.ed25519.sig",
                "a-cypherpunks-manifesto.txt",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn after() {
        Command::cargo_bin("sqv")
            .unwrap()
            .current_dir(path::Path::new("tests").join("data"))
            .args(&[
                "--keyring",
                "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
                "--not-after",
                "2018-08-13",
                "a-cypherpunks-manifesto.txt.ed25519.sig",
                "a-cypherpunks-manifesto.txt",
            ])
            .assert()
            .failure();
    }
}
