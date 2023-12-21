use anyhow::Result;
use chrono::Local;
use clap::{Args, Parser};
use clap_stdin::MaybeStdin;
use log::{debug, info, error};
use std::env;
use teloxide::{net::Download, prelude::*};
use timetracksync::parse_records;
use tokio::fs::File;

use crate::cli::Cli;

use super::Command;

#[derive(Debug, Args, Clone)]
pub struct ServeTelegramArgs {
    #[clap(
        long,
        short,
        help = "Telegram bot token. If not provided, will be read from env var TELOXIDE_TOKEN"
    )]
    token: Option<String>,

    #[clap(
        long,
        short,
        help = "Telegram handles authorized to use this bot. Must be @-prefixed, is case-sensitive"
    )]
    authorized_handles: Vec<String>,

    embedded_username: String,
    embedded_password: MaybeStdin<String>,
}

pub async fn handle(args: ServeTelegramArgs) -> Result<()> {
    let bot = match args.token {
        Some(token) => Bot::new(token),
        None => Bot::from_env(),
    };

    teloxide::repl(bot, |bot: Bot, msg: Message| {
        // This is needed because the args to the repl have to be static, which the args struct is not.
        let args = Cli::parse();
        let args = match args.command {
            Command::ServeTelegram(args) => args,
            _ => unreachable!(),
        };

        async move {
            let chat_id = msg.chat.id;

            let from = msg.from().expect("Message has no sender");
            let authorized = match from.mention() {
                Some(mention) => args.authorized_handles.contains(&mention),
                None => false,
            };
            if !authorized {
                info!("Rejecting unauthorized user {:?}", from);
                bot.send_message(chat_id, "User is not authorized!").await?;
                return Ok(());
            }
            debug!("User passed authorization");

            info!("Handling message from @{:?}", from.mention());
            let document = msg.document();
            let document = match document {
                Some(d) => d,
                None => {
                    debug!("Received message without document");
                    bot.send_message(chat_id, "You must send a file").await?;
                    return Ok(());
                }
            };
            let is_valid_type = document
                .file_name
                .as_ref()
                .map(|f| f.ends_with(".csv"))
                .unwrap_or(false);
            if !is_valid_type {
                info!("Rejecting invalid file name {:?}", document.file_name);
                bot.send_message(chat_id, "You must send a .csv file")
                    .await?;
                return Ok(());
            }
            debug!("Sent file is valid");

            let file = bot.get_file(&document.file.id).await?;
            let path =
                env::temp_dir().join(format!("{}.csv", Local::now().format("%Y-%m-%d_%H-%M-%S")));
            let mut dst = File::create(&path).await?;
            debug!("Downloading CSV file [{:?}]", path);
            bot.download_file(&file.path, &mut dst).await?;
            drop(dst); // File handle is already closed. This prevents runtime errors.

            debug!("Reading file contents");
            let records = parse_records(&path).expect("Failed to parse records");
            let processed_records = timetracksync::process_recods(records);
            bot.send_message(chat_id, format!("Uploading {} records...", processed_records.len()))
                .await?;
            let result = timetracksync::upload(processed_records, &args.embedded_username, &args.embedded_password).await;
            let message = match &result {
                Ok(_) => "Successfully uploaded records!".to_string(),
                Err(e) => format!("Failed to upload records: {}", e),
            };
            bot.send_message(chat_id, message).await?;

            if let Err(e) = result {
                error!("Failed to upload records: {:?}", e);
            }

            Ok(())
        }
    })
    .await;

    Ok(())
}
