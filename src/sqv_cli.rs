/// Command-line parser for sqv.

use std::path::PathBuf;

use clap::{Command, CommandFactory, Parser};

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

    SqvCommand::command().version(sqv_version)
}

#[derive(Parser)]
#[command(
    name="sqv",
    about = "sqv is a command-line OpenPGP signature verification tool",
    after_help = "\
TIMESTAMPs must be given in ISO 8601 format \
(e.g. '2017-03-04T13:25:35Z', '2017-03-04T13:25', \
'20170304T1325+0830', '2017-03-04', '2017031', ...).  \
If no timezone is specified, UTC is assumed.",
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
    /// If a date is given, 23:59:59 is used for the time.
    /// [default: now]
    #[clap(
        long,
        value_name = "TIMESTAMP")]
    pub not_after: Option<String>,

    /// Consider signatures created before TIMESTAMP as invalid.
    /// If a date is given, 00:00:00 is used for the time.
    /// [default: no constraint]
    #[clap(
        long,
        value_name = "TIMESTAMP")]
    pub not_before: Option<String>,

    /// The number of valid signatures to return success.
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
