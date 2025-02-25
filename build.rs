use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::Result;

use clap::ValueEnum;

use clap_complete::Shell;

mod cli {
    include!("src/cli/mod.rs");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let mut sqv = cli::build();
    generate_shell_completions(&mut sqv).unwrap();
    generate_man_pages(&mut sqv).unwrap();
}

/// Variable name to control the asset out directory with.
const ASSET_OUT_DIR: &str = "ASSET_OUT_DIR";

/// Returns the directory to write the given assets to.
fn asset_out_dir(asset: &str) -> Result<PathBuf> {
    println!("cargo:rerun-if-env-changed={}", ASSET_OUT_DIR);
    let outdir: PathBuf =
        env::var_os(ASSET_OUT_DIR).unwrap_or_else(
            || env::var_os("OUT_DIR").expect("OUT_DIR not set")).into();
    if outdir.exists() && ! outdir.is_dir() {
        return Err(
            anyhow::anyhow!("{}={:?} is not a directory",
                            ASSET_OUT_DIR, outdir));
    }

    let path = outdir.join(asset);
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Generates shell completions.
fn generate_shell_completions(sqv: &mut clap::Command) -> Result<()> {
    let path = asset_out_dir("shell-completions")?;

    for shell in Shell::value_variants() {
        clap_complete::generate_to(*shell, sqv, "sqv", &path)?;
    };

    println!("cargo:warning=shell completions written to {}", path.display());
    Ok(())
}

/// Generates man pages.
fn generate_man_pages(sqv: &clap::Command) -> Result<()> {
    let path = asset_out_dir("man-pages")?.join("sqv.1");

    let man = clap_mangen::Man::new(sqv.clone());
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer)?;

    std::fs::write(&path, &buffer)?;

    println!("cargo:warning=man page written to {}", path.display());
    Ok(())
}
