//! A simple signature verification program.
//!
//! See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=872271 for
//! the motivation.

use std::io;
use std::process::exit;
use std::path::PathBuf;

use chrono::{DateTime, offset::Utc};
use anyhow::Context;

use clap::FromArgMatches;

use sequoia_openpgp as openpgp;

use crate::openpgp::{
    Cert,
    KeyHandle,
    Result,
    parse::Parse,
};
use crate::openpgp::parse::stream::{
    DetachedVerifierBuilder,
    MessageLayer,
    MessageStructure,
    VerificationHelper,
    GoodChecksum,
    VerificationError,
    VerifierBuilder,
};
use crate::openpgp::cert::prelude::*;

mod cli;

struct VHelper {
    not_before: Option<std::time::SystemTime>,
    not_after: std::time::SystemTime,

    good: usize,
    total: usize,
    threshold: usize,

    keyrings: Vec<PathBuf>,
}

impl std::fmt::Debug for VHelper {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("VHelper")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("good", &self.good)
            .field("total", &self.total)
            .field("threshold", &self.threshold)
            .field("keyrings", &self.keyrings)
            .finish()
    }
}

impl VHelper {
    fn new(threshold: usize,
           not_before: Option<std::time::SystemTime>,
           not_after: std::time::SystemTime,
           keyrings: Vec<PathBuf>) -> Self {
        VHelper {
            not_before: not_before,
            not_after: not_after,
            good: 0,
            total: 0,
            threshold: threshold,
            keyrings: keyrings,
        }
    }
}

impl VerificationHelper for VHelper {
    fn get_certs(&mut self, ids: &[crate::KeyHandle]) -> Result<Vec<Cert>> {
        let mut certs = Vec::with_capacity(ids.len());

        // Load relevant keys from the keyring.
        for filename in self.keyrings.iter() {
            for cert in CertParser::from_file(filename)
                .with_context(|| format!("Failed to parse keyring {:?}",
                                         filename))?
                .unvalidated_cert_filter(|cert, _| {
                    // We don't skip keys that are valid (not revoked,
                    // alive, etc.) so that
                    cert.keys().key_handles(ids.iter()).next().is_some()
                })
            {
                certs.push(cert.with_context(|| {
                    format!("Malformed certificate in keyring {:?}", filename)
                })?);
            }
        }

        // Dedup.  To avoid cloning the certificates, we don't use
        // Vec::dedup.
        certs.sort_by(|a, b| a.fingerprint().cmp(&b.fingerprint()));
        let count = certs.len();
        let (certs, errs) = certs.into_iter().fold(
            (Vec::with_capacity(count), Vec::new()),
            |(mut certs, mut errs), a| {
                if certs.is_empty() {
                    certs.push(a);
                } else if certs[certs.len() - 1].fingerprint() == a.fingerprint() {
                    // Merge `a` into the last element.
                    match certs.pop().expect("non-empty vec").merge_public(a) {
                        Ok(cert) => certs.push(cert),
                        Err(err) => errs.push(err),
                    }
                } else {
                    certs.push(a);
                }

                (certs, errs)
            });

        if !errs.is_empty() {
            eprintln!("Error merging duplicate keys:");
            for err in errs.iter() {
                eprintln!("  {}", err);
            }
            Err(errs.into_iter().next().expect("non-empty vec"))
        } else {
            Ok(certs)
        }
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        use self::VerificationError::*;

        let mut signers = Vec::with_capacity(2);
        let mut verification_err = None;

        for layer in structure.into_iter() {
            match layer {
                MessageLayer::SignatureGroup { results } =>
                    for result in results {
                        self.total += 1;
                        match result {
                            Ok(GoodChecksum { sig, ka, .. }) => {
                                match (sig.signature_creation_time(),
                                                self.not_before,
                                                self.not_after)
                                {
                                    (None, _, _) => {
                                        eprintln!("Malformed signature:");
                                        print_error_chain(&anyhow::anyhow!(
                                            "no signature creation time"));
                                    },
                                    (Some(t), Some(not_before), not_after) => {
                                        if t < not_before {
                                            eprintln!(
                                                "Signature by {:X} was created before \
                                                 the --not-before date.",
                                                ka.key().fingerprint());
                                        } else if t > not_after {
                                            eprintln!(
                                                "Signature by {:X} was created after \
                                                 the --not-after date.",
                                                ka.key().fingerprint());
                                        } else {
                                            signers.push(ka.cert().fingerprint());
                                        }
                                    }
                                    (Some(t), None, not_after) => {
                                        if t > not_after {
                                            eprintln!(
                                                "Signature by {:X} was created after \
                                                 the --not-after date.",
                                                ka.key().fingerprint());
                                        } else {
                                            signers.push(ka.cert().fingerprint());
                                        }
                                    }
                                };
                            }
                            Err(MalformedSignature { error, .. }) => {
                                eprintln!("Signature is malformed:");
                                print_error_chain(&error);
                            }
                            Err(MissingKey { sig, .. }) => {
                                let issuers = sig.get_issuers();
                                eprintln!("Missing key {:X}, which is needed to \
                                           verify signature.",
                                          issuers.first().unwrap());
                            }
                            Err(UnboundKey { cert, error, .. }) => {
                                eprintln!("Signing key on {:X} is not bound:",
                                          cert.fingerprint());
                                print_error_chain(&error);
                            }
                            Err(BadKey { ka, error, .. }) => {
                                eprintln!("Signing key on {:X} is bad:",
                                          ka.cert().fingerprint());
                                print_error_chain(&error);
                            }
                            Err(BadSignature { error, .. }) => {
                                eprintln!("Verifying signature:");
                                print_error_chain(&error);
                                if verification_err.is_none() {
                                    verification_err = Some(error)
                                }
                            }

                            Err(UnknownSignature { sig, .. }) => {
                                eprintln!("Verifying signature:");
                                print_error_chain(sig.error());
                                if verification_err.is_none() {
                                    verification_err =
                                        Some(anyhow::anyhow!("{}", sig.error()));
                                }
                            }

                            Err(e) => {
                                eprintln!("Verifying signature: {}", e);
                                if verification_err.is_none() {
                                    verification_err =
                                        Some(anyhow::anyhow!("{}", e));
                                }
                            }
                        }
                    }
                MessageLayer::Compression { .. } => (),
                _ => unreachable!(),
            }
        }

        // Dedup the keys so that it is not possible to exceed the
        // threshold by duplicating signatures or by using the same
        // key.
        signers.sort();
        signers.dedup();

        self.good = signers.len();
        for signer in signers {
            println!("{:X}", signer);
        }

        Ok(())
    }
}

fn print_error_chain(err: &anyhow::Error) {
    eprintln!("           {}", err);
    err.chain().skip(1).for_each(|cause| eprintln!("  because: {}", cause));
}


fn main() -> Result<()> {
    let matches = cli::build().get_matches();
    let cli = cli::SqvCommand::from_arg_matches(&matches)?;

    if cli.data.is_none() && cli.detached.is_none()
        && ! cli.message && ! cli.cleartext
    {
        return Err(anyhow::anyhow!(
            "Either `--signature-file`, `--message`, or `--cleartext` \
             must be given."));
    }

    let verbose = cli.verbose;

    let good_threshold = cli.signatures;
    if good_threshold < 1 {
        eprintln!("Value passed to --signatures must be >= 1 (got: {:?}).",
                  good_threshold);
        exit(2);
    }

    let not_before: Option<std::time::SystemTime> =
        if let Some(t) = cli.not_before {
            Some(parse_iso8601(&t, chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap())
                 .context(format!("Bad value passed to --not-before: {:?}", t))?
                 .into())
        } else {
            None
        };
    let not_after: std::time::SystemTime =
        if let Some(t) = cli.not_after {
            Some(parse_iso8601(&t, chrono::NaiveTime::from_hms_opt(23, 59, 59).unwrap())
                 .context(format!("Bad value passed to --not-after: {:?}", t))?
                 .into())
        } else {
            None
        }.unwrap_or_else(std::time::SystemTime::now);

    let h = VHelper::new(good_threshold, not_before, not_after, cli.keyring);

    let t = cli.policy_as_of.as_ref()
        .map(|at| at.to_system_time(std::time::SystemTime::now()))
        .transpose()
        .with_context(|| format!("Error parsing --policy-as-of: {}",
                                 cli.policy_as_of.unwrap()))?
        .unwrap_or_else(std::time::SystemTime::now);

    let mut p = sequoia_policy_config::ConfiguredStandardPolicy::at(t);
    p.parse_default_config()?;
    let p = p.build();

    // Dispatch.
    let h = if cli.data.is_some() || cli.detached.is_some() {
        let sig = cli.detached.as_ref().unwrap_or(&cli.file);
        let data = cli.data.as_ref().unwrap_or(&cli.file);

        let mut v =
            DetachedVerifierBuilder::from_file(sig)?
            .with_policy(&p, None, h)?;
        v.verify_file(data)?;
        v.into_helper()
    } else {
        assert!(cli.message || cli.cleartext);
        let mut sink: Box<dyn io::Write> = if let Some(n) = &cli.output {
            Box::new(std::fs::File::options()
                .write(true)
                .create(cli.overwrite) // choose create() when allowing overwrite
                .create_new(!cli.overwrite) // else insist on new file
                .open(n)?)
        } else {
            Box::new(io::stdout())
        };

        let mut v =
            VerifierBuilder::from_file(&cli.file)?
            .with_policy(&p, None, h)?;
        io::copy(&mut v, &mut sink)?;
        v.into_helper()
    };

    if verbose {
        eprintln!("{} of {} signatures are valid (threshold is: {}).",
                  h.good, h.total, good_threshold);
    }

    exit(if h.good >= good_threshold { 0 } else { 1 });
}

/// Parses the given string depicting a ISO 8601 timestamp.
fn parse_iso8601(s: &str, pad_date_with: chrono::NaiveTime)
                 -> Result<DateTime<Utc>>
{
    // If you modify this function this function, synchronize the
    // changes with the copy in sqv.rs!
    for f in &[
        "%Y-%m-%dT%H:%M:%S%#z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M%#z",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H%#z",
        "%Y-%m-%dT%H",
        "%Y%m%dT%H%M%S%#z",
        "%Y%m%dT%H%M%S",
        "%Y%m%dT%H%M%#z",
        "%Y%m%dT%H%M",
        "%Y%m%dT%H%#z",
        "%Y%m%dT%H",
    ] {
        if f.ends_with("%#z") {
            if let Ok(d) = DateTime::parse_from_str(s, *f) {
                return Ok(d.into());
            }
        } else {
            if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, *f) {
                return Ok(DateTime::from_naive_utc_and_offset(d, Utc));
            }
        }
    }
    for f in &[
        "%Y-%m-%d",
        "%Y-%m",
        "%Y-%j",
        "%Y%m%d",
        "%Y%m",
        "%Y%j",
        "%Y",
    ] {
        if let Ok(d) = chrono::NaiveDate::parse_from_str(s, *f) {
            return Ok(DateTime::from_naive_utc_and_offset(d.and_time(pad_date_with), Utc));
        }
    }
    Err(anyhow::anyhow!("Malformed ISO8601 timestamp: {}", s))
}

#[test]
fn test_parse_iso8601() {
    let z = chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap();
    parse_iso8601("2017-03-04T13:25:35Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35+08:30", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35", z).unwrap();
    parse_iso8601("2017-03-04T13:25Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25", z).unwrap();
    // parse_iso8601("2017-03-04T13Z", z).unwrap(); // XXX: chrono doesn't like
    // parse_iso8601("2017-03-04T13", z).unwrap(); // ditto
    parse_iso8601("2017-03-04", z).unwrap();
    // parse_iso8601("2017-03", z).unwrap(); // ditto
    parse_iso8601("2017-031", z).unwrap();
    parse_iso8601("20170304T132535Z", z).unwrap();
    parse_iso8601("20170304T132535+0830", z).unwrap();
    parse_iso8601("20170304T132535", z).unwrap();
    parse_iso8601("20170304T1325Z", z).unwrap();
    parse_iso8601("20170304T1325", z).unwrap();
    // parse_iso8601("20170304T13Z", z).unwrap(); // ditto
    // parse_iso8601("20170304T13", z).unwrap(); // ditto
    parse_iso8601("20170304", z).unwrap();
    // parse_iso8601("201703", z).unwrap(); // ditto
    parse_iso8601("2017031", z).unwrap();
    // parse_iso8601("2017", z).unwrap(); // ditto
}
