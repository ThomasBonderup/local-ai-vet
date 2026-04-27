use std::{default, path::PathBuf};

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "evidence-triage")]
#[command(about = "Local-first AI-assisted evidence triage for security review")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Triage {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        output: PathBuf,

        #[arg(long, default_value = "gwen2.5-coder")]
        model: String,

        #[arg(long, default_value = "http://localhost:11434")]
        ollama_url: String,
    },
}
