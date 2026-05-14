use anyhow::{Context, Result};
use std::path::Path;

use crate::{
    adapters::{default_adapters, traits::BundleContext},
    evidence::{
        model::{EvidencePack, EvidenceRecord},
        raw::RawRepo,
    },
    io::discover::discover_bundle_files,
};

pub fn convert_gateway_release_bundle(bundle_dir: &Path) -> Result<EvidencePack> {
    let ctx = BundleContext {
        run_id: infer_run_id(bundle_dir),
        repo_name: "rust-iot-gateway".to_string(),
        bundle_dir: bundle_dir.to_path_buf(),
    };
    let records = collect_evidence_records(bundle_dir, &ctx)
        .context("failed to collect evidence records from gateway release bundle")?;

    Ok(EvidencePack {
        schema_version: "local-ai-vet.evidence-pack.v1".to_string(),
        run_id: ctx.run_id,
        repo: RawRepo {
            name: "rust-iot-gateway".to_string(),
            language: Some("rust".to_string()),
            commit: None,
            branch: None,
        },
        evidence: records,
    })
}

pub fn collect_evidence_records(
    bundle_dir: &Path,
    ctx: &BundleContext,
) -> Result<Vec<EvidenceRecord>> {
    let adapters = default_adapters();
    let files = discover_bundle_files(&bundle_dir).context("failed to discover bundle files")?;

    let mut records: Vec<EvidenceRecord> = Vec::new();

    for file in files {
        for adapter in &adapters {
            if adapter.supports(&file) {
                let mut parsed = adapter.parse(&file, &ctx).with_context(|| {
                    format!(
                        "failed to parse evidence file '{}' with adapters '{}'",
                        file.display(),
                        adapter.name()
                    )
                })?;
                records.append(&mut parsed);
            }
        }
    }
    Ok(records)
}

fn infer_run_id(bundle_dir: &Path) -> String {
    bundle_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown-run")
        .to_string()
}
