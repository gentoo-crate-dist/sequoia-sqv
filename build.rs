use anyhow::Result;

use clap::ValueEnum;

use clap_complete::Shell;

use sequoia_man::asset_out_dir;

mod cli {
    include!("src/cli/mod.rs");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let mut sqv = cli::build();
    generate_shell_completions(&mut sqv).unwrap();
    generate_man_pages(&mut sqv).unwrap();
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
fn generate_man_pages(sqv: &mut clap::Command) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let builder = sequoia_man::man::Builder::new(sqv, version, None);

    let man_pages = asset_out_dir("man-pages")?;

    sequoia_man::generate_man_pages(&man_pages, &builder).unwrap();
    Ok(())
}
