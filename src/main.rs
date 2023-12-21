mod cli;

use clap::Parser;
use cli::Cli;

use anyhow::Result;
use log::LevelFilter;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};

#[tokio::main]
async fn main() -> Result<()> {
    TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    let _ = dotenvy::dotenv();

    let args = Cli::parse();
    cli::handle(args).await?;
    return Ok(());
}
