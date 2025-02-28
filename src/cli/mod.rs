/// Command-line parser for sqv.

use std::path::PathBuf;

use clap::{Command, CommandFactory, Parser};

use sequoia_policy_config::ConfiguredStandardPolicy;

// The argument parser.
pub fn build() -> Command {
    let sqv_version = Box::leak(
        format!(
            "{} (sequoia-openpgp {}, using {})",
            env!("CARGO_PKG_VERSION"),
            sequoia_openpgp::VERSION,
            sequoia_openpgp::crypto::backend()
        )
        .into_boxed_str(),
    ) as &str;

    SqvCommand::command()
        .version(sqv_version)
        // To improve readability limit the width of the text columns.
        .max_term_width(100)
}

#[derive(Parser)]
#[command(
    name="sqv",
    about = "An OpenPGP signature verification tool",
    long_about = format!("\
An OpenPGP signature verification tool

sqv is a simple signature verification tool.  It checks that \
signatures are valid, and correctly issued by one of the certificates \
in the specified keyring.

By default, one signature must be valid.  This can be changed using \
the `--signatures` arguments.

A signature is valid if a signing-capable key can verify the \
signature.  The signing-capable key must be correctly bound to a \
certificate in the keyring, and it must not be revoked, or expired. \
The certificate must not be revoked or expired.  The signature, the \
signing-capable key and the certificate must all be valid according to \
the cryptographic policy.

By default, sqv configures the cryptographic policy using <{}>.  That \
can be overwritten by setting the {} environment variable to an \
alternate file.  The path must be absolute.  The file's format is \
described here: <https://docs.rs/sequoia-policy-config/>.

In some cases, the user expects signatures to be made within a certain \
temporal window.  This can be enforced using the `--not-before` and \
`--not-after` arguments.  The TIMESTAMPs must be given in ISO 8601 \
format (e.g. `2017-03-04T13:25:35Z`, `2017-03-04T13:25`, \
`20170304T1325+0830`, `2017-03-04`, `2017031`, etc.).  If no timezone \
is specified, UTC is assumed.

Exits with a non-zero status if the specified number of signatures \
could not be verified.
",
                         ConfiguredStandardPolicy::CONFIG_FILE,
                         ConfiguredStandardPolicy::ENV_VAR),
    arg_required_else_help = true,
    disable_colored_help = true,
)]
pub struct SqvCommand {
    /// A keyring.
    #[clap(
        long,
        value_name = "FILE",
        required = true)]
    pub keyring: Vec<PathBuf>,


    /// Consider signatures created after TIMESTAMP as invalid.
    ///
    /// If only a date is given, 23:59:59 is used for the time.
    /// [default: now]
    #[clap(
        long,
        value_name = "TIMESTAMP")]
    pub not_after: Option<String>,

    /// Consider signatures created before TIMESTAMP as invalid.
    ///
    /// If only a date is given, 00:00:00 is used for the time.
    /// [default: no constraint]
    #[clap(
        long,
        value_name = "TIMESTAMP")]
    pub not_before: Option<String>,

    /// The number of valid signatures to return success.
    ///
    /// Note: this counts the number of certificates, not signatures.
    /// Thus, if two signatures are issued by the same certificate,
    /// they only count once.
    #[clap(
        long,
        short = 'n',
        value_name = "N",
        default_value_t = 1)]
    pub signatures: usize,

    /// File containing the detached signature.
    #[clap(
        value_name = "SIG-FILE")]
    pub sig_file: PathBuf,

    /// File to verify.
    #[clap(
        value_name = "FILE")]
    pub file: PathBuf,

    /// Be verbose.
    #[clap(
        long,
        short = 'v')]
    pub verbose: bool,
}
