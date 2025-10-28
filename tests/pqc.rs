use std::path;

use assert_cmd::Command;
use predicates::prelude::*;

use sequoia_openpgp as openpgp;
use openpgp::types::PublicKeyAlgorithm;

/// Verifies a detached signature (using MLDAS65+Ed25519 artifacts).
#[test]
fn detached_pqc_mldsa65_signature() {
    if ! PublicKeyAlgorithm::MLDSA65_Ed25519.is_supported() {
        eprintln!("MLDSA65_Ed25519 is not supported, skipping");
        return;
    }

    let p = tempfile::tempdir().expect("can create temporary directory");
    let policy = p.path().join("policy.toml");
    std::fs::write(&policy, "").expect("can write to temp file");

    Command::cargo_bin("sqv").expect("have sqv")
        .env("SEQUOIA_CRYPTO_POLICY", &policy)
        .current_dir(path::Path::new("tests").join("data"))
        .args(&[
            "--keyring",
            "pqc_mldsa65.pk.pgp",
            "--signature-file=msg_pqc_mldsa65.sig",
            "msg.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::eq(
            b"B387AFD1BA509D943A6A1FF727DBD140BE3311BD7C1AE09F98F964C4C8BA706F\n" as &[u8]));
}


