use anyhow::{Context, Result};
use serde_json::{Value, json};
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
                    .unwrap_or("unknown");

                let package_version = vuln
                    .pointer("/package/version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let advisory_id = vuln
                    .pointer("/advisory/id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                records.push(EvidenceRecord {
                    evidence_id: format!(
                        "vuln:cargo-audit:{advisory_id}:{package_name}:{package_version}"
                    ),
                    run_id: ctx.run_id.clone(),
                    kind: EvidenceKind::Vulnerability,
                    source: EvidenceSource {
                        file: "cargo-audit.json".to_string(),
                        pointer: Some(format!("/vulnerabilities/list/{idx}")),
                        sha256: None,
                    },
                    subject: json!({
                        "ecosystem": "cargo",
                        "package": package_name,
                        "version": package_version,
                        "advisory_id": advisory_id
                    }),
                    claim: json!({
                        "advisory_id": advisory_id,
                        "title": vuln.pointer("/advisory/title"),
                        "description": vuln.pointer("/advisory/description"),
                        "date": vuln.pointer("/advisory/date"),
                        "aliases": vuln.pointer("/advisory/aliases"),
                        "url": vuln.pointer("/advisory/url"),
                        "patched_versions": vuln.pointer("/versions/patched"),
                        "source_pointer": format!("/vulnerabilities/list/{idx}")
                    }),
                    confidence: EvidenceConfidence::ToolReported,
                });
            }
        }

        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn test_context() -> BundleContext {
        BundleContext {
            run_id: "test-run".to_string(),
            repo_name: "rust-iot-gateway".to_string(),
            bundle_dir: std::env::temp_dir(),
        }
    }

    fn parse_fixture(content: &str) -> Vec<EvidenceRecord> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after UNIX epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("local-ai-vet-cargo-audit-{unique}"));
        fs::create_dir_all(&dir).expect("failed to create temp fixture dir");
        let path = dir.join("cargo-audit.json");
        fs::write(&path, content).expect("failed to write cargo-audit fixture");

        let records = CargoAuditAdapter
            .parse(&path, &test_context())
            .expect("failed to parse cargo-audit fixture");

        fs::remove_file(&path).ok();
        fs::remove_dir(&dir).ok();

        records
    }

    fn fixture_vulnerability(
        package: &str,
        version: &str,
        advisory_id: &str,
        title: &str,
    ) -> Value {
        json!({
            "package": {
                "name": package,
                "version": version
            },
            "advisory": {
                "id": advisory_id,
                "title": title,
                "aliases": [format!("GHSA-{advisory_id}")],
                "url": format!("https://example.invalid/{advisory_id}"),
                "date": "2026-05-12",
                "description": format!("Description for {advisory_id}")
            },
            "versions": {
                "patched": [">=0.103.13, <0.104.0-alpha.1"]
            }
        })
    }

    #[test]
    fn emits_one_vulnerability_record_per_advisory() {
        let content = json!({
            "vulnerabilities": {
                "list": [
                    fixture_vulnerability(
                        "rustls-webpki",
                        "0.103.10",
                        "RUSTSEC-2026-0104",
                        "Reachable panic in certificate revocation list parsing"
                    ),
                    fixture_vulnerability(
                        "rustls-webpki",
                        "0.103.10",
                        "RUSTSEC-2026-0098",
                        "Name constraints for URI names were incorrectly accepted"
                    ),
                    fixture_vulnerability(
                        "rustls-webpki",
                        "0.103.10",
                        "RUSTSEC-2026-0099",
                        "Name constraints were accepted for wildcard certificates"
                    )
                ]
            }
        })
        .to_string();

        let records = parse_fixture(&content);

        assert_eq!(records.len(), 3);
        let advisory_ids: Vec<_> = records
            .iter()
            .map(|record| record.claim["advisory_id"].as_str().unwrap())
            .collect();
        assert_eq!(
            advisory_ids,
            vec![
                "RUSTSEC-2026-0104",
                "RUSTSEC-2026-0098",
                "RUSTSEC-2026-0099"
            ]
        );

        let evidence_ids: Vec<_> = records
            .iter()
            .map(|record| record.evidence_id.as_str())
            .collect();
        assert_eq!(
            evidence_ids,
            vec![
                "vuln:cargo-audit:RUSTSEC-2026-0104:rustls-webpki:0.103.10",
                "vuln:cargo-audit:RUSTSEC-2026-0098:rustls-webpki:0.103.10",
                "vuln:cargo-audit:RUSTSEC-2026-0099:rustls-webpki:0.103.10"
            ]
        );

        let source_pointers: Vec<_> = records
            .iter()
            .map(|record| record.source.pointer.as_deref().unwrap())
            .collect();
        assert_eq!(
            source_pointers,
            vec![
                "/vulnerabilities/list/0",
                "/vulnerabilities/list/1",
                "/vulnerabilities/list/2"
            ]
        );
    }

    #[test]
    fn includes_advisory_identity_in_evidence_ids() {
        let content = json!({
            "vulnerabilities": {
                "list": [
                    fixture_vulnerability(
                        "rustls-webpki",
                        "0.103.10",
                        "RUSTSEC-2026-0104",
                        "Reachable panic in certificate revocation list parsing"
                    ),
                    fixture_vulnerability(
                        "another-crate",
                        "1.2.3",
                        "RUSTSEC-2026-0001",
                        "Another vulnerability"
                    )
                ]
            }
        })
        .to_string();

        let records = parse_fixture(&content);

        assert_eq!(records.len(), 2);
        let evidence_ids: Vec<_> = records
            .iter()
            .map(|record| record.evidence_id.as_str())
            .collect();
        assert_eq!(
            evidence_ids,
            vec![
                "vuln:cargo-audit:RUSTSEC-2026-0104:rustls-webpki:0.103.10",
                "vuln:cargo-audit:RUSTSEC-2026-0001:another-crate:1.2.3"
            ]
        );
    }
}
