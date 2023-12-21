use anyhow::Result;
use clap::Args;
use log::info;
use std::path::PathBuf;
use timetracksync::{process_recods, parse_records, upload};
use clap_stdin::MaybeStdin;

#[derive(Debug, Args, Clone)]
pub struct IngestArgs {
    file: PathBuf,

    embedded_username: String,
    embedded_password: MaybeStdin<String>,
}

pub(crate) async fn handle(args: IngestArgs) -> Result<()> {
    info!("Ingesting {:?}", args.file);
    let records = parse_records(&args.file).expect("Failed to parse records");

    info!("Ingested {} records", records.len());
    let processed_records = process_recods(records);
    info!("Processed to {} records", processed_records.len());

    upload(
        processed_records,
        &args.embedded_username,
        &args.embedded_password.to_string(),
    ).await?;

    Ok(())
}
