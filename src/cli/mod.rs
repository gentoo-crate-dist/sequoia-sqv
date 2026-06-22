use std::path::PathBuf;

use clap::{Command, CommandFactory, Parser};

use sequoia_policy_config::ConfiguredStandardPolicy;

mod time;

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

sqv can verify detached signatures, inline-signed messages, and
messages using the Cleartext Signature Framework.

To verify detached signatures, use the `--signature-file` argument
followed by the path to the detached signature file, and give the data
file as first positional argument:

  $ sqv --keyring=... --signature-file=image.iso.sig image.iso

To verify an inline-signed message, use the `--message` argument, and
give the path to the inline-signed message as first positional
argument.  When verifying an inline-signed `--output` has to be given:

  $ sqv --keyring=... --output=authenticated.txt \\
        --message signed.pgp

To verify a message using the Cleartext Signature Framework, use the
`--cleartext` argument, and give the path to the message as first
positional argument.  When verifying an inline-signed `--output` has
to be given:

  $ sqv --keyring=... --output=authenticated.txt \\
        --cleartext message.txt

Finally, there is a legacy way to verify detached signatures, where
the path to the signature file and the path to the data file are given
as positional arguments.  This form is deprecated, prefer the explicit
`--signature-file` form.

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
    after_help = "Examples:

# Verify a detached signature.
$ sqv --keyring=trusted.pgp --signature-file=document.sig \\
                              document.txt

# Verify a detached signature, legacy interface.
$ sqv --keyring=trusted.pgp document.sig document.txt

# Verify a signed message.
$ sqv --keyring trusted.pgp --message document.pgp

# Verify a message using the Cleartext Signature Framework.
$ sqv --keyring trusted.pgp --cleartext document.pgp
",
    arg_required_else_help = true,
    disable_colored_help = true,
)]
#[clap(group(clap::ArgGroup::new("kind")
             .args(&["detached", "message", "cleartext"]).required(false)))]
pub struct SqvCommand {
    #[clap(
        long,
        value_name = "FILE",
        conflicts_with_all = ["detached", "data"],
        required_unless_present_any = ["detached", "data"],
        help = "Write to FILE",
        long_help = "\
Write to FILE.

This is required when verifying an inline signed message (using \
--message) and a cleartext signed message (using --cleartext) and is \
forbidden when verifying a detached signature (using
--signature-file)."
    )]
    pub output: Option<PathBuf>,

    #[clap(
        long,
        help = "Overwrite the output file if it already exists"
        )]
    pub overwrite: bool,

    #[clap(
        long = "signature-file",
        value_name = "SIG",
        help = "Verify a detached signature file"
    )]
    pub detached: Option<PathBuf>,

    #[clap(
        long = "message",
        value_name = "SIG",
        help = "Verify an inline signed message"
    )]
    pub message: bool,

    #[clap(
        long = "cleartext",
        value_name = "SIG",
        help = "Verify a cleartext-signed message"
    )]
    pub cleartext: bool,

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

    /// The inline-signed message, message using the Cleartext
    /// Signature Framework, or data file.
    #[clap(value_name = "FILE")]
    pub file: PathBuf,

    /// In the legacy way of invoking sqv, the signature file is given
    /// as first positional argument, and the data file as second.
    #[clap(
        hide = true,
        value_name = "DATA-FILE",
        conflicts_with_all = ["detached", "message", "cleartext"],
    )]
    pub data: Option<PathBuf>,

    /// Be verbose.
    #[clap(
        long,
        short = 'v')]
    pub verbose: bool,

    #[clap(
        long = "time",
        allow_hyphen_values = true,
        value_name = "TIMESTAMP",
        help = "Set the reference time as an ISO 8601 formatted timestamp",
        long_help = "\
Set the reference time as an ISO 8601 formatted timestamp or \
relative offset.

This sets the reference time for the sqv session.  Normally, \
sqv uses the current time.  This argument allows you to use a \
different time.

This time is also used as the default value for --not-after and \
--policy-as-of, and it is passed to the signature verifier as \
the reference time for evaluating whether keys and certificates \
are valid.

TIME is interpreted as an ISO 8601 timestamp.  To set the \
time to January 1, 2007 at midnight UTC, you can do:

$ sqv --time 20070101 --keyring keyring.pgp --message msg.pgp

An offset can also be used.  For instance, to set the time to \
one year ago, do:

$ sqv --time -1y --keyring keyring.pgp --message msg.pgp
"
    )]
    pub time: Option<time::Time>,

    #[clap(
        long = "policy-as-of",
        allow_hyphen_values = true,
        value_name = "TIMESTAMP",
        help = "Select the cryptographic policy as of the specified time",
        long_help = "\
Select the cryptographic policy as of the specified time

The time is \
expressed as an ISO 8601 formatted timestamp.  The policy determines \
what cryptographic constructs are allowed.

If you are working with a message that sq rejects, because it is \
protected by cryptographic constructs that are now considered broken, \
you can use this option to select a different cryptographic policy.  \
If you are relying on the cryptography, e.g., you are verifying a \
signature, then you should only do this if you are confident that the \
message hasn't been tampered with.

TIME is interpreted as an ISO 8601 timestamp.  To set the \
policy time to January 1, 2007 at midnight UTC, you can do:

$ sqv --policy-as-of 20070101 --message msg.pgp

Defaults to the current time.
",
    )]
    pub policy_as_of: Option<time::Time>,
}
