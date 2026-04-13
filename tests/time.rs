#[cfg(test)]
mod integration {
    use std::path;

    use assert_cmd::Command;
    use predicates::prelude::*;

    // The ed25519 detached signature on a-cypherpunks-manifesto.txt was
    // created on 2018-08-14.
    //
    // The inline-signed (.pgp) and cleartext-signed (.csf) variants
    // have a "not live until 2025-03-06" constraint.
    //
    // The SHA-1 detached signature was created around 2007 and requires
    // a relaxed policy (e.g. --policy-as-of 2008) to verify.

    const ED25519_KEYRING: &str =
        "emmelie-dorothea-dina-samantha-awina-ed25519.pgp";
    const ED25519_SIG: &str =
        "a-cypherpunks-manifesto.txt.ed25519.sig";
    const ED25519_FPR: &[u8] =
        b"8E8C33FA4626337976D97978069C0C348DD82C19\n";

    const SHA1_KEYRING: &str = "mrpast.key";
    const SHA1_SIG: &str = "a-cypherpunks-manifesto.txt.sha1.sig";
    const SHA1_FPR: &[u8] =
        b"40A0E8E64DCC61D977DD86D7165F9B3B60351FBC\n";

    const PLAINTEXT: &str = "a-cypherpunks-manifesto.txt";
    const INLINE_MSG: &str = "a-cypherpunks-manifesto.pgp";
    const CLEARTEXT_MSG: &str = "a-cypherpunks-manifesto.csf";

    fn sqv() -> Command {
        let mut cmd = Command::cargo_bin("sqv").expect("have sqv");
        cmd.current_dir(path::Path::new("tests").join("data"));
        cmd
    }

    #[test]
    fn time() {
        let policy = path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("time-test-empty-policy.toml");
        std::fs::write(&policy, "").unwrap();

        // --time just after the ed25519 signature date: succeeds.
        sqv()
            .args(&["--keyring", ED25519_KEYRING,
                     "--time", "2018-08-15",
                     ED25519_SIG, PLAINTEXT])
            .assert()
            .success()
            .stdout(predicate::eq(ED25519_FPR));

        // --time before the signature date: not-after defaults to
        // ref_time, so the signature is "in the future" → fails.
        sqv()
            .args(&["--keyring", ED25519_KEYRING,
                     "--time", "2018-08-13",
                     ED25519_SIG, PLAINTEXT])
            .assert()
            .failure();

        // Explicit --not-after overrides the --time default.
        sqv()
            .args(&["--keyring", ED25519_KEYRING,
                     "--time", "2018-08-15",
                     "--not-after", "2018-08-15",
                     ED25519_SIG, PLAINTEXT])
            .assert()
            .success()
            .stdout(predicate::eq(ED25519_FPR));

        // Without --time, the SHA-1 signature is rejected by current policy.
        sqv()
            .env("SEQUOIA_CRYPTO_POLICY", &policy)
            .args(&["--keyring", SHA1_KEYRING,
                     SHA1_SIG, PLAINTEXT])
            .assert()
            .failure();

        // --time in 2008 relaxes the policy so SHA-1 is accepted.
        sqv()
            .env("SEQUOIA_CRYPTO_POLICY", &policy)
            .args(&["--keyring", SHA1_KEYRING,
                     "--time", "2008-08-03",
                     SHA1_SIG, PLAINTEXT])
            .assert()
            .success()
            .stdout(predicate::eq(SHA1_FPR));

        // Explicit --policy-as-of overrides the --time default.
        sqv()
            .env("SEQUOIA_CRYPTO_POLICY", &policy)
            .args(&["--keyring", SHA1_KEYRING,
                     "--time", "2008-08-03",
                     "--policy-as-of", "2025-01-01",
                     SHA1_SIG, PLAINTEXT])
            .assert()
            .failure();

        // Large negative relative offsets that resolve before the 2018
        // signature regardless of when the suite runs, one per suffix.
        for offset in &["-100y", "-1200m", "-5000w", "-40000d", "-4000000000s"] {
            sqv()
                .args(&["--keyring", ED25519_KEYRING,
                         "--time", offset,
                         ED25519_SIG, PLAINTEXT])
                .assert()
                .failure();
        }

        // Inline-signed message with --time after the liveness date.
        // The message has a "not live until 2025-03-06" constraint.
        let tmpdir = tempfile::tempdir().unwrap();
        let auth = tmpdir.path().join("inline.txt");
        sqv()
            .args(&["--keyring", ED25519_KEYRING,
                     "--time", "2025-03-07",
                     "--output", &auth.display().to_string(),
                     "--message", INLINE_MSG])
            .assert()
            .success()
            .stdout(predicate::eq(ED25519_FPR));
        let reference = path::Path::new("tests").join("data")
            .join(PLAINTEXT);
        assert_eq!(std::fs::read(&auth).unwrap(),
                   std::fs::read(&reference).unwrap());

        // Cleartext-signed message with --time after the liveness date.
        let auth = tmpdir.path().join("cleartext.txt");
        sqv()
            .args(&["--keyring", ED25519_KEYRING,
                     "--time", "2025-03-07",
                     "--output", &auth.display().to_string(),
                     "--cleartext", CLEARTEXT_MSG])
            .assert()
            .success()
            .stdout(predicate::eq(ED25519_FPR));
        let auth = String::from_utf8(std::fs::read(&auth).unwrap())
            .unwrap();
        let reference = String::from_utf8(
            std::fs::read(&reference).unwrap(),
        ).unwrap();
        assert_eq!(auth.trim_end(), reference.trim_end());
    }
}
