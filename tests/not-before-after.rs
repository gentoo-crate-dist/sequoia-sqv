#[cfg(test)]
mod integration {
    use assert_cli::Assert;
    use std::path;

    #[test]
    fn unconstrained() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(&[
                "--keyring",
                "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
                "a-cypherpunks-manifesto.txt.ed25519.sig",
                "a-cypherpunks-manifesto.txt",
            ])
            .stdout()
            .is("8E8C33FA4626337976D97978069C0C348DD82C19")
            .unwrap();
    }

    #[test]
    fn in_interval() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(&[
                "--keyring",
                "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
                "--not-before",
                "2018-08-14",
                "--not-after",
                "2018-08-15",
                "a-cypherpunks-manifesto.txt.ed25519.sig",
                "a-cypherpunks-manifesto.txt",
            ])
            .stdout()
            .is("8E8C33FA4626337976D97978069C0C348DD82C19")
            .unwrap();
    }

    #[test]
    fn before() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(&[
                "--keyring",
                "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
                "--not-before",
                "2018-08-15",
                "a-cypherpunks-manifesto.txt.ed25519.sig",
                "a-cypherpunks-manifesto.txt",
            ])
            .fails()
            .unwrap();
    }

    #[test]
    fn after() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(&[
                "--keyring",
                "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
                "--not-after",
                "2018-08-13",
                "a-cypherpunks-manifesto.txt.ed25519.sig",
                "a-cypherpunks-manifesto.txt",
            ])
            .fails()
            .unwrap();
    }
}
