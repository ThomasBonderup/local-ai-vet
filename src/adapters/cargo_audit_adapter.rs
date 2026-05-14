use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

use crate::adapters::traits::{BundleContext, EvidenceAdapter};
use crate::evidence::model::{EvidenceConfidence, EvidenceKind, EvidenceRecord, EvidenceSource};

pub struct CargoAuditAdapter;

impl EvidenceAdapter for CargoAuditAdapter {
    fn name(&self) -> &'static str {
        "cargo-audit"
    }

    fn supports(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == "cargo-audit.json")
            .unwrap_or(false)
    }

    fn parse(&self, path: &Path, ctx: &BundleContext) -> Result<Vec<EvidenceRecord>> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read path: {}", path.display()))?;
        let json: Value = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse JSON file: {}", path.display()))?;

        let mut records = Vec::new();

        if let Some(vulns) = json
            .pointer("/vulnerabilities/list")
            .and_then(|v| v.as_array())
        {
            for (idx, vuln) in vulns.iter().enumerate() {
                let package_name = vuln
                    .pointer("/package/name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unkown");

                let package_version = vuln
                    .pointer("/package/version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let advisory_id = vuln
                    .pointer("/advisory/id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let evidence_id = format!(
                    "vuln:cargo-audit:{}:{}:{}",
                    advisory_id, package_name, package_version
                );

                records.push(EvidenceRecord {
                    evidence_id,
                    run_id: ctx.run_id.clone(),
                    kind: EvidenceKind::Vulnerability,
                    source: EvidenceSource {
                        file: "cargo-audit.json".to_string(),
                        pointer: Some(format!("/vulnerabilities/list/{idx}")),
                        sha256: None,
                    },
                    subject: serde_json::json!({
                        "ecosystem": "cargo",
                        "package": package_name,
                        "version": package_version
                    }),
                    claim: serde_json::json!({
                        "advisory_id": advisory_id,
                        "title": vuln.pointer("/advisory/title"),
                        "url": vuln.pointer("/advisory/url"),
                        "patched_versions": vuln.pointer("/versions/patched"),
                        "aliases": vuln.pointer("/advisory/aliases")
                    }),
                    confidence: EvidenceConfidence::ToolReported,
                });
            }
        }
        Ok(records)
    }
}
