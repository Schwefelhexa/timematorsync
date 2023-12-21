mod serve_telegram;
mod ingest;

use anyhow::Result;
use clap::{Parser, Subcommand};

use self::{serve_telegram::ServeTelegramArgs, ingest::IngestArgs};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,

}

#[derive(Debug, Subcommand, Clone)]
pub(crate) enum Command {
    ServeTelegram(ServeTelegramArgs),
    Ingest(IngestArgs),
}

pub(crate) async fn handle(args: Cli) -> Result<()> {
    match args.command {
        Command::ServeTelegram(args) => serve_telegram::handle(args).await?,
        Command::Ingest(ingest_args) => ingest::handle(ingest_args).await?,
    };

    Ok(())
}
