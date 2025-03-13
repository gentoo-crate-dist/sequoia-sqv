use assert_cmd::Command;
use predicates::prelude::*;
use std::path;

/// Verifies a detached signature.
#[test]
fn detached() {
    Command::cargo_bin("sqv").expect("have sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "--signature-file=a-cypherpunks-manifesto.txt.ed25519.sig",
            "a-cypherpunks-manifesto.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::eq(
            b"8E8C33FA4626337976D97978069C0C348DD82C19\n" as &[u8]));

    // Conflicts with --output.
    Command::cargo_bin("sqv").expect("have sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "--output=authenticated.txt",
            "--signature-file=a-cypherpunks-manifesto.txt.ed25519.sig",
            "a-cypherpunks-manifesto.txt",
        ])
        .assert()
        .failure();
}

/// Verifies a detached signature using the legacy form.
#[test]
fn detached_legacy() {
    Command::cargo_bin("sqv").expect("have sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "a-cypherpunks-manifesto.txt.ed25519.sig",
            "a-cypherpunks-manifesto.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::eq(
            b"8E8C33FA4626337976D97978069C0C348DD82C19\n" as &[u8]));
}

/// Verifies an inline-signed message.
#[test]
fn inline_signed_message() {
    let p = tempfile::tempdir().unwrap();
    let auth = p.path().join("authenticated.txt").display().to_string();

    Command::cargo_bin("sqv").expect("have sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "--output", &auth,
            "--message",
            "a-cypherpunks-manifesto.pgp",
        ])
        .assert()
        .success()
        .stdout(predicate::eq(
            b"8E8C33FA4626337976D97978069C0C348DD82C19\n" as &[u8]));

    let reference = path::Path::new("tests").join("data")
        .join("a-cypherpunks-manifesto.txt");
    assert_eq!(std::fs::read(&auth).unwrap(),
               std::fs::read(&reference).unwrap());

    // Requires --output.
    Command::cargo_bin("sqv").expect("have sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "--message",
            "a-cypherpunks-manifesto.pgp",
        ])
        .assert()
        .failure();
}

/// Verifies an cleartext-signed message.
#[test]
fn cleartext_signed_message() {
    let p = tempfile::tempdir().unwrap();
    let auth = p.path().join("authenticated.txt").display().to_string();

    Command::cargo_bin("sqv").expect("have sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "--output", &auth,
            "--cleartext",
            "a-cypherpunks-manifesto.csf",
        ])
        .assert()
        .success()
        .stdout(predicate::eq(
            b"8E8C33FA4626337976D97978069C0C348DD82C19\n" as &[u8]));

    let reference = path::Path::new("tests").join("data")
        .join("a-cypherpunks-manifesto.txt");
    let auth =
        String::from_utf8(std::fs::read(&auth).unwrap()).unwrap();
    let reference =
        String::from_utf8(std::fs::read(&reference).unwrap()).unwrap();
    assert_eq!(auth.trim_end(), reference.trim_end());

    // Requires --output.
    Command::cargo_bin("sqv").expect("have sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "--cleartext",
            "a-cypherpunks-manifesto.csf",
        ])
        .assert()
        .failure();
}

/// Verifies overwrite switch.
#[test]
fn overwrite() {
    let p = tempfile::tempdir().unwrap();
    let auth = p.path().join("authenticated.txt").display().to_string();

    // create an output file
    Command::cargo_bin("sqv").expect("have sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "--output", &auth,
            "--cleartext",
            "a-cypherpunks-manifesto.csf",
        ])
        .assert()
        .success()
        .stdout(predicate::eq(
            b"8E8C33FA4626337976D97978069C0C348DD82C19\n" as &[u8]));

    // repeat procedure - this has to fail
    Command::cargo_bin("sqv").expect("have sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "--output", &auth,
            "--cleartext",
            "a-cypherpunks-manifesto.csf",
        ])
        .assert()
        .failure();

    // repeat again - this time with '--overwrite', this should succeed
    // like the first incarnation (eg: same output)
    Command::cargo_bin("sqv").expect("have sqv")
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
            "--output", &auth,
            "--overwrite",
            "--cleartext",
            "a-cypherpunks-manifesto.csf",
        ])
        .assert()
        .success()
        .stdout(predicate::eq(
            b"8E8C33FA4626337976D97978069C0C348DD82C19\n" as &[u8]));
}
