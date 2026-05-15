use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::adapters::traits::EvidenceAdapter;
use crate::evidence::model::{EvidenceConfidence, EvidenceKind, EvidenceRecord, EvidenceSource};

pub struct CycloneDxAdapter;

impl EvidenceAdapter for CycloneDxAdapter {
    fn name(&self) -> &'static str {
        "cyclone-dx-sbom"
    }

    fn supports(&self, path: &std::path::Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == "sbom.cdx.json")
            .unwrap_or(false)
    }

    fn parse(
        &self,
        path: &std::path::Path,
        ctx: &super::traits::BundleContext,
    ) -> Result<Vec<EvidenceRecord>> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read path: {}", path.display()))?;
        let json: Value = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse JSON file: {}", path.display()))?;

        let mut records = Vec::new();

        let mut by_bom_ref: BTreeMap<String, SbomComponent> = BTreeMap::new();
        // let mut by_package_version: BTreeMap<(String, String, String), Vec<Value>> = BTreeMap::new();

        if let Some(components) = json.pointer("/components").and_then(|c| c.as_array()) {
            for (idx, component) in components.iter().enumerate() {
                let name = component
                    .pointer("/name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let version = component
                    .pointer("/version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let bom_ref = component
                    .pointer("/bom-ref")
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| {
                        // Fallback. Better than losing the component completely.
                        // You can also choose to skip components without bom-ref.
                        "unknown-bom-ref"
                    })
                    .to_string();

                let purl = component
                    .pointer("/purl")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);

                let ecosystem = infer_ecosystem(purl.as_deref());

                let component_type = component
                    .pointer("/type")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);

                let scope = component
                    .pointer("/scope")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);

                let source_pointer = format!("/components/{idx}");

                let sbom_component = SbomComponent {
                    bom_ref: bom_ref.clone(),
                    ecosystem: ecosystem.clone(),
                    name: name.clone(),
                    version: version.clone(),
                    purl,
                    component_type,
                    scope,
                    source_pointer,
                };

                by_bom_ref.insert(bom_ref, sbom_component);
            }
        }

        for component in by_bom_ref.values() {
            let evidence_id = format!(
                "component:{}:{}:{}",
                component.ecosystem, component.name, component.version
            );

            records.push(EvidenceRecord {
                evidence_id,
                run_id: ctx.run_id.clone(),
                kind: EvidenceKind::Component,
                source: EvidenceSource {
                    file: "sbom.cdx.json".to_string(),
                    pointer: Some(component.source_pointer.clone()),
                    sha256: None,
                },
                subject: serde_json::json!({
                    "ecosystem": component.ecosystem,
                    "name": component.name,
                    "version": component.version,
                }),
                claim: serde_json::json!({
                    "component_present": true,
                    "bom_ref": component.bom_ref,
                    "purl": component.purl,
                    "type": component.component_type,
                    "scope": component.scope,
                }),
                confidence: EvidenceConfidence::ToolReported,
            });
        }
        Ok(records)
    }
}

#[derive(Debug, Clone)]
struct SbomComponent {
    bom_ref: String,
    ecosystem: String,
    name: String,
    version: String,
    purl: Option<String>,
    component_type: Option<String>,
    scope: Option<String>,
    source_pointer: String,
}

fn infer_ecosystem(purl: Option<&str>) -> String {
    match purl {
        Some(purl) if purl.starts_with("pkg:cargo/") => "cargo".to_string(),
        Some(purl) if purl.starts_with("pkg:npm/") => "npm".to_string(),
        Some(purl) if purl.starts_with("pkg:pypi/") => "pypi".to_string(),
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::traits::BundleContext;
    use serde_json::json;
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
        let dir = std::env::temp_dir().join(format!("local-ai-vet-cyclone-dx-{unique}"));
        fs::create_dir_all(&dir).expect("failed to create temp fixture dir");
        let path = dir.join("sbom.cdx.json");
        fs::write(&path, content).expect("failed to write CycloneDX fixture");

        let records = CycloneDxAdapter
            .parse(&path, &test_context())
            .expect("failed to parse CycloneDX fixture");

        fs::remove_file(&path).ok();
        fs::remove_dir(&dir).ok();

        records
    }

    #[test]
    fn emits_component_record_with_cyclone_dx_metadata() {
        let content = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "bom-ref": "pkg:cargo/zip@2.4.2",
                    "name": "zip",
                    "version": "2.4.2",
                    "purl": "pkg:cargo/zip@2.4.2",
                    "scope": "excluded"
                }
            ]
        })
        .to_string();

        let records = parse_fixture(&content);

        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.evidence_id, "component:cargo:zip:2.4.2");
        assert_eq!(record.run_id, "test-run");
        assert!(matches!(record.kind, EvidenceKind::Component));
        assert_eq!(record.source.file, "sbom.cdx.json");
        assert_eq!(record.source.pointer.as_deref(), Some("/components/0"));
        assert_eq!(record.source.sha256, None);
        assert_eq!(record.subject["ecosystem"], "cargo");
        assert_eq!(record.subject["name"], "zip");
        assert_eq!(record.subject["version"], "2.4.2");
        assert_eq!(record.claim["component_present"], true);
        assert_eq!(record.claim["bom_ref"], "pkg:cargo/zip@2.4.2");
        assert_eq!(record.claim["purl"], "pkg:cargo/zip@2.4.2");
        assert_eq!(record.claim["type"], "library");
        assert_eq!(record.claim["scope"], "excluded");
        assert!(matches!(record.confidence, EvidenceConfidence::ToolReported));
    }
}
