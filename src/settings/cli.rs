use clap::Parser;

use crate::settings::Settings;

// todo: add a merge command to merge old toml to new toml with new stuff if new stuff exists.
/// pretty simple CLI for creating the config file
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, author)]
struct Args {
    /// Create a new freshly baked config file in the current directory
    #[arg(short, long)]
    generate: bool,
}

pub fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.generate {
        Settings::create_settings_file()?;
        tracing::info!(
            "Settings file created successfully! Check it out before running the app again :)"
        );
        std::process::exit(0);
    }

    Ok(())
}
