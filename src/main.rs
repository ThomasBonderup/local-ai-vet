mod cli;
mod evidence;
mod llm;
mod triage;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command};
use evidence::raw::RawEvidencePack;
use llm::ollama::OllamaClient;
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Triage {
            input,
            output,
            model,
            ollama_url,
        } => {
            let raw = fs::read_to_string(&input)
                .with_context(|| format!("failed to read evidence pack: {}", input.display()))?;
            let evidence_pack: RawEvidencePack = serde_json::from_str(&raw)?;
            let client = OllamaClient::new(ollama_url, model);
            let triage = client.triage(&evidence_pack).await?;

            let json = serde_json::to_string_pretty(&triage)?;
            fs::write(&output, json)?;

            println!("Wrote AI triage output to {}", output.display());
        }
    }
    println!("Hello, world!");
    Ok(())
}
