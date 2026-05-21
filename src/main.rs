mod adapters;
mod cli;
mod evidence;
mod io;
mod llm;
mod report;
mod triage;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command};
use llm::ollama::OllamaClient;
use std::fs;

use crate::{
    evidence::{
        audit::{ArtifactVerificationStatus, require_verified_bundle},
        bundle_to_evidence::convert_gateway_release_bundle,
        model::EvidencePack,
        pack::write_evidence_pack,
    },
    report::markdown::render_markdown_report,
    triage::{candidate::AiTriageResult, validate::validate_ai_triage_refs},
};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::BundleToEvidence { bundle_dir, output } => {
            let pack = convert_gateway_release_bundle(&bundle_dir)
                .context("failed to convert bundle to evidence")?;

            write_evidence_pack(&pack, &output).context("failed to write evidence pack")?;

            println!("Converted bundle to evidence: {}", output.display());
        }
        Command::VerifyBundle { bundle_dir } => {
            let verification = require_verified_bundle(&bundle_dir)
                .context("failed to verify bundle artifact integrity")?;

            println!(
                "Bundle artifact verification passed: {} artifacts checked.",
                verification.artifacts.len()
            );
            for artifact in verification.artifacts {
                if artifact.status == ArtifactVerificationStatus::Matched {
                    println!("verified {} {}", artifact.expected_sha256, artifact.path);
                }
            }
        }
        Command::Triage {
            input,
            output,
            model,
            ollama_url,
        } => {
            let pack = fs::read_to_string(&input)
                .with_context(|| format!("failed to read evidence pack: {}", input.display()))?;
            let evidence_pack: EvidencePack = serde_json::from_str(&pack)
                .with_context(|| format!("failed to parse evidence pack: {}", input.display()))?;
            let client = OllamaClient::new(ollama_url, model);
            let triage = client.triage(&evidence_pack).await?;

            let output_json = serde_json::to_string_pretty(&triage)
                .context("failed to serialize AI triage result")?;

            fs::write(&output, output_json).with_context(|| {
                format!("failed to write AI triage output: {}", output.display())
            })?;

            println!("Wrote AI triage output to {}", output.display());
        }
        Command::Validate { input, triage } => {
            let raw_pack = fs::read_to_string(&input)
                .with_context(|| format!("failed to read evidence pack: {}", input.display()))?;

            let evidence_pack: EvidencePack = serde_json::from_str(&raw_pack)
                .with_context(|| format!("failed to parse evidence pack: {}", input.display()))?;

            let raw_triage = fs::read_to_string(&triage)
                .with_context(|| format!("failed to read AI triage file: {}", triage.display()))?;

            let ai_triage: AiTriageResult = serde_json::from_str(&raw_triage)
                .with_context(|| format!("failed to parse AI triage JSON: {}", triage.display()))?;

            validate_ai_triage_refs(&evidence_pack, &ai_triage)
                .context("AI triage validation failed")?;

            println!("AI triage output is valid.");
        }
        Command::Report { triage, output } => {
            let raw_triage = fs::read_to_string(&triage)
                .with_context(|| format!("failed to read AI triage file: {}", triage.display()))?;

            let ai_triage: AiTriageResult = serde_json::from_str(&raw_triage)
                .with_context(|| format!("failed to parse AI triage JSON: {}", triage.display()))?;

            let markdown = render_markdown_report(&ai_triage);

            fs::write(&output, markdown).with_context(|| {
                format!("failed to write Markdown report: {}", output.display())
            })?;

            println!("Wrote Markdown review report to {}", output.display());
        }
    }
    Ok(())
}
