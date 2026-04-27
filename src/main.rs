mod cli;

use clap::Parser;
use cli::{Cli, Command};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Triage {
            input,
            output,
            model,
            ollama_url,
        } => {
            println!("input: {}", input.display());
            println!("output: {}", output.display());
            println!("model: {}", model);
            println!("ollama_url {}", ollama_url);
        }
    }
    println!("Hello, world!");
}
