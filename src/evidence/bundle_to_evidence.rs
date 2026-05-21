use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::{
    adapters::{default_adapters, traits::BundleContext},
    evidence::{
        audit::{
            add_source_digests, artifact_digest_map, provenance_records, repo_from_bundle_metadata,
            verify_bundle,
        },
        model::{EvidencePack, EvidenceRecord},
    },
    io::discover::discover_bundle_files,
};

pub fn convert_gateway_release_bundle(bundle_dir: &Path) -> Result<EvidencePack> {
    let ctx = BundleContext {
        run_id: infer_run_id(bundle_dir),
        repo_name: "rust-iot-gateway".to_string(),
        bundle_dir: bundle_dir.to_path_buf(),
    };
    let mut records = collect_evidence_records(bundle_dir, &ctx)
        .context("failed to collect evidence records from gateway release bundle")?;
    let verification = verify_bundle(bundle_dir).context("failed to verify bundle artifacts")?;
    if let Some(verification) = verification.as_ref() {
        if !verification.verified {
            anyhow::bail!("bundle artifact verification failed");
        }
    } else {
        eprintln!(
            "warning: bundle has no artifact-digests.txt; evidence source integrity is not verified"
        );
    }
    let digests = artifact_digest_map(bundle_dir).context("failed to read artifact digests")?;
    add_source_digests(&mut records, &digests);

    add_related_component_evidence_ids(&mut records);
    let mut records = filter_unrelated_components(records);
    let mut provenance = provenance_records(bundle_dir, &ctx, verification.as_ref())
        .context("failed to build provenance evidence records")?;
    add_source_digests(&mut provenance, &digests);
    records.append(&mut provenance);
    let repo = repo_from_bundle_metadata(bundle_dir, &ctx.repo_name)
        .context("failed to read bundle repository metadata")?;

    Ok(EvidencePack {
        schema_version: "local-ai-vet.evidence-pack.v1".to_string(),
        run_id: ctx.run_id,
        repo,
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

pub fn add_related_component_evidence_ids(records: &mut [EvidenceRecord]) {
    let component_ids: BTreeMap<(String, String, String), String> = records
        .iter()
        .filter(|record| is_component_kind(&record.kind))
        .filter_map(|record| {
            let ecosystem = record.subject.get("ecosystem")?.as_str()?.to_string();
            let name = record.subject.get("name")?.as_str()?.to_string();
            let version = record.subject.get("version")?.as_str()?.to_string();
            Some(((ecosystem, name, version), record.evidence_id.clone()))
        })
        .collect();

    for record in records.iter_mut().filter(|record| {
        matches!(
            record.kind,
            crate::evidence::model::EvidenceKind::Vulnerability
        )
    }) {
        let Some(package) = record.subject.get("package").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = record.subject.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        let ecosystem = record
            .subject
            .get("ecosystem")
            .and_then(|v| v.as_str())
            .unwrap_or("cargo");
        let Some(component_id) = component_ids.get(&(
            ecosystem.to_string(),
            package.to_string(),
            version.to_string(),
        )) else {
            continue;
        };

        if let Value::Object(claim) = &mut record.claim {
            claim.insert(
                "related_component_evidence_id".to_string(),
                Value::String(component_id.clone()),
            );
        }
    }
}

pub fn filter_unrelated_components(records: Vec<EvidenceRecord>) -> Vec<EvidenceRecord> {
    let vulnerability_count = records
        .iter()
        .filter(|record| {
            matches!(
                record.kind,
                crate::evidence::model::EvidenceKind::Vulnerability
            )
        })
        .count();

    if vulnerability_count == 0 {
        return records;
    }

    let related_component_ids: BTreeSet<String> = records
        .iter()
        .filter(|record| {
            matches!(
                record.kind,
                crate::evidence::model::EvidenceKind::Vulnerability
            )
        })
        .filter_map(|record| {
            record
                .claim
                .get("related_component_evidence_id")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .collect();

    records
        .into_iter()
        .filter(|record| {
            !is_component_kind(&record.kind) || related_component_ids.contains(&record.evidence_id)
        })
        .collect()
}

fn is_component_kind(kind: &crate::evidence::model::EvidenceKind) -> bool {
    matches!(
        kind,
        crate::evidence::model::EvidenceKind::Component
            | crate::evidence::model::EvidenceKind::SbomComponent
    )
}

fn infer_run_id(bundle_dir: &Path) -> String {
    bundle_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown-run")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::model::{
        EvidenceConfidence, EvidenceKind, EvidenceRecord, EvidenceSource,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn vulnerability(advisory_id: &str, package: &str, version: &str) -> EvidenceRecord {
        EvidenceRecord {
            evidence_id: format!("vuln:cargo-audit:{advisory_id}:{package}:{version}"),
            run_id: "test-run".to_string(),
            kind: EvidenceKind::Vulnerability,
            source: EvidenceSource {
                file: "cargo-audit.json".to_string(),
                pointer: Some("/vulnerabilities/list/0".to_string()),
                sha256: None,
            },
            subject: json!({
                "ecosystem": "cargo",
                "package": package,
                "version": version,
                "advisory_id": advisory_id
            }),
            claim: json!({
                "advisory_id": advisory_id,
                "title": format!("Advisory {advisory_id}")
            }),
            confidence: EvidenceConfidence::ToolReported,
        }
    }

    fn component(name: &str, version: &str) -> EvidenceRecord {
        EvidenceRecord {
            evidence_id: format!("component:cargo:{name}:{version}"),
            run_id: "test-run".to_string(),
            kind: EvidenceKind::Component,
            source: EvidenceSource {
                file: "sbom.cdx.json".to_string(),
                pointer: Some("/components/0".to_string()),
                sha256: None,
            },
            subject: json!({
                "ecosystem": "cargo",
                "name": name,
                "version": version
            }),
            claim: json!({
                "component_present": true,
                "scope": "required"
            }),
            confidence: EvidenceConfidence::ToolReported,
        }
    }

    fn temp_bundle() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after UNIX epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("local-ai-vet-bundle-{unique}"));
        fs::create_dir_all(&dir).expect("failed to create temp bundle");
        dir
    }

    fn write_json(path: &Path, value: serde_json::Value) {
        fs::write(path, serde_json::to_string_pretty(&value).unwrap())
            .expect("failed to write JSON fixture");
    }

    fn digest_file(path: &Path) -> String {
        let bytes = fs::read(path).expect("failed to read fixture for digest");
        format!("{:x}", Sha256::digest(bytes))
    }

    fn write_digest_file(dir: &Path, files: &[&str]) {
        let body = files
            .iter()
            .map(|file| format!("{}  {}", digest_file(&dir.join(file)), file))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(dir.join("artifact-digests.txt"), format!("{body}\n"))
            .expect("failed to write digest fixture");
    }

    #[test]
    fn links_vulnerabilities_to_matching_components_and_filters_unrelated_components() {
        let mut records = vec![
            vulnerability("RUSTSEC-2026-0104", "rustls-webpki", "0.103.10"),
            vulnerability("RUSTSEC-2026-0098", "rustls-webpki", "0.103.10"),
            vulnerability("RUSTSEC-2026-0099", "rustls-webpki", "0.103.10"),
            component("rustls-webpki", "0.103.10"),
            component("zip", "2.4.2"),
        ];

        add_related_component_evidence_ids(&mut records);
        let records = filter_unrelated_components(records);

        let evidence_ids: Vec<_> = records
            .iter()
            .map(|record| record.evidence_id.as_str())
            .collect();
        assert_eq!(
            evidence_ids,
            vec![
                "vuln:cargo-audit:RUSTSEC-2026-0104:rustls-webpki:0.103.10",
                "vuln:cargo-audit:RUSTSEC-2026-0098:rustls-webpki:0.103.10",
                "vuln:cargo-audit:RUSTSEC-2026-0099:rustls-webpki:0.103.10",
                "component:cargo:rustls-webpki:0.103.10"
            ]
        );

        for record in records
            .iter()
            .filter(|record| matches!(record.kind, EvidenceKind::Vulnerability))
        {
            assert_eq!(
                record.claim["related_component_evidence_id"],
                "component:cargo:rustls-webpki:0.103.10"
            );
        }
    }

    #[test]
    fn keeps_components_when_no_vulnerabilities_exist() {
        let records = vec![
            component("rustls-webpki", "0.103.10"),
            component("zip", "2.4.2"),
        ];

        let records = filter_unrelated_components(records);

        let evidence_ids: Vec<_> = records
            .iter()
            .map(|record| record.evidence_id.as_str())
            .collect();
        assert_eq!(
            evidence_ids,
            vec![
                "component:cargo:rustls-webpki:0.103.10",
                "component:cargo:zip:2.4.2"
            ]
        );
    }

    #[test]
    fn keeps_vulnerabilities_without_matching_components() {
        let mut records = vec![
            vulnerability("RUSTSEC-2026-0104", "rustls-webpki", "0.103.10"),
            component("zip", "2.4.2"),
        ];

        add_related_component_evidence_ids(&mut records);
        let records = filter_unrelated_components(records);

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].evidence_id,
            "vuln:cargo-audit:RUSTSEC-2026-0104:rustls-webpki:0.103.10"
        );
        assert!(
            records[0]
                .claim
                .get("related_component_evidence_id")
                .is_none()
        );
    }

    #[test]
    fn converts_bundle_with_verified_source_digests_and_provenance() {
        let dir = temp_bundle();
        write_json(
            &dir.join("sbom.cdx.json"),
            json!({
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "bom-ref": "pkg:cargo/rustls-webpki@0.103.10",
                        "name": "rustls-webpki",
                        "version": "0.103.10",
                        "purl": "pkg:cargo/rustls-webpki@0.103.10",
                        "scope": "required"
                    }
                ]
            }),
        );
        write_json(
            &dir.join("cargo-audit.json"),
            json!({
                "vulnerabilities": {
                    "list": [
                        {
                            "package": { "name": "rustls-webpki", "version": "0.103.10" },
                            "advisory": {
                                "id": "RUSTSEC-2026-0104",
                                "title": "Reachable panic in certificate revocation list parsing",
                                "aliases": ["GHSA-82j2-j2ch-gfr8"],
                                "url": "https://example.invalid/RUSTSEC-2026-0104",
                                "date": "2026-04-22",
                                "description": "CRL panic"
                            },
                            "versions": { "patched": [">=0.103.13"] }
                        }
                    ]
                }
            }),
        );
        write_json(
            &dir.join("manifest.json"),
            json!({
                "generated_at_utc": "20260512T130225Z",
                "bundle_id": "test-bundle",
                "git_head": "abc123",
                "git_branch": "main",
                "git_tree_state": "clean",
                "package": {
                    "name": "rust-iot-gateway",
                    "version": "0.1.0",
                    "cargo_lock_sha256": "lock-digest"
                },
                "audit": {
                    "command": "cargo audit --json",
                    "exit_code": 1,
                    "advisory_db_head": "db-head"
                }
            }),
        );
        write_json(
            &dir.join("provenance.json"),
            json!({
                "generated_at_utc": "20260512T130225Z",
                "bundle_id": "test-bundle",
                "source": {
                    "repository": "rust-iot-gateway",
                    "package_name": "rust-iot-gateway",
                    "package_version": "0.1.0",
                    "git_head": "abc123",
                    "git_branch": "main",
                    "git_tree_state": "clean",
                    "cargo_lock_sha256": "lock-digest"
                }
            }),
        );
        write_digest_file(
            &dir,
            &[
                "sbom.cdx.json",
                "cargo-audit.json",
                "manifest.json",
                "provenance.json",
            ],
        );

        let pack = convert_gateway_release_bundle(&dir).expect("bundle should convert");

        assert_eq!(pack.repo.commit.as_deref(), Some("abc123"));
        assert_eq!(pack.repo.branch.as_deref(), Some("main"));
        assert!(pack.evidence.iter().any(|record| {
            record.evidence_id == "provenance:artifact-integrity"
                && record.claim["verified"].as_bool() == Some(true)
        }));
        assert!(pack.evidence.iter().any(|record| {
            record.source.file == "cargo-audit.json" && record.source.sha256.is_some()
        }));
        assert!(pack.evidence.iter().any(|record| {
            record.source.file == "sbom.cdx.json" && record.source.sha256.is_some()
        }));

        fs::remove_dir_all(&dir).ok();
    }
}
