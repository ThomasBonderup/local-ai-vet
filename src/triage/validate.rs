use crate::evidence::model::{EvidenceKind, EvidencePack};
use crate::triage::candidate::AiTriageResult;

use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};

pub fn collect_evidence_ids(pack: &EvidencePack) -> HashSet<String> {
    pack.evidence
        .iter()
        .map(|record| record.evidence_id.clone())
        .collect()
}

pub fn validate_ai_triage_refs(pack: &EvidencePack, triage: &AiTriageResult) -> Result<()> {
    let evidence_ids = collect_evidence_ids(pack);
    let evidence_kinds: HashMap<_, _> = pack
        .evidence
        .iter()
        .map(|record| (record.evidence_id.as_str(), &record.kind))
        .collect();
    let vulnerability_ids: HashSet<_> = pack
        .evidence
        .iter()
        .filter(|record| matches!(record.kind, EvidenceKind::Vulnerability))
        .map(|record| record.evidence_id.as_str())
        .collect();
    let vulnerabilities_exist = !vulnerability_ids.is_empty();

    if vulnerabilities_exist && triage.finding_candidates.len() != vulnerability_ids.len() {
        bail!(
            "AI triage produced {} candidates, but evidence pack contains {} vulnerability records",
            triage.finding_candidates.len(),
            vulnerability_ids.len()
        );
    }

    for candidate in &triage.finding_candidates {
        if candidate.evidence_refs.is_empty() {
            bail!("candidate {} has no evidence_refs", candidate.candidate_id)
        }
        let mut references_vulnerability = false;
        for evidence_ref in &candidate.evidence_refs {
            if let Some(stripped) = evidence_ref.strip_prefix("evidence_id:") {
                bail!(
                    "candidate {} references evidence id with unsupported prefix: {} (use exact id: {})",
                    candidate.candidate_id,
                    evidence_ref,
                    stripped
                )
            }
            if !evidence_ids.contains(evidence_ref) {
                bail!(
                    "candidate {} references unknown evidence id: {}",
                    candidate.candidate_id,
                    evidence_ref
                )
            }
            match evidence_kinds.get(evidence_ref.as_str()) {
                Some(EvidenceKind::Provenance) => {
                    bail!(
                        "candidate {} references provenance evidence as finding evidence: {}",
                        candidate.candidate_id,
                        evidence_ref
                    )
                }
                Some(EvidenceKind::Vulnerability) => {
                    references_vulnerability = true;
                }
                _ => {}
            }
        }

        if vulnerabilities_exist && !references_vulnerability {
            bail!(
                "candidate {} must reference at least one vulnerability evidence id",
                candidate.candidate_id
            );
        }

        if candidate.uncertainty.trim().is_empty() {
            bail!(
                "candidate {} has empty uncertainty field",
                candidate.candidate_id
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        evidence::{
            model::{
                EvidenceConfidence, EvidenceKind, EvidencePack, EvidenceRecord, EvidenceSource,
            },
            raw::RawRepo,
        },
        triage::candidate::{AiFindingCandidate, ModelInfo},
    };
    use serde_json::json;

    fn component_pack() -> EvidencePack {
        EvidencePack {
            schema_version: "local-ai-vet.evidence-pack.v1".to_string(),
            run_id: "test-run".to_string(),
            repo: RawRepo {
                name: "rust-iot-gateway".to_string(),
                language: Some("rust".to_string()),
                commit: None,
                branch: None,
            },
            evidence: vec![EvidenceRecord {
                evidence_id: "component:cargo:zip:2.4.2".to_string(),
                run_id: "test-run".to_string(),
                kind: EvidenceKind::Component,
                source: EvidenceSource {
                    file: "sbom.cdx.json".to_string(),
                    pointer: Some("/components/0".to_string()),
                    sha256: None,
                },
                subject: json!({
                    "ecosystem": "cargo",
                    "name": "zip",
                    "version": "2.4.2"
                }),
                claim: json!({
                    "component_present": true
                }),
                confidence: EvidenceConfidence::ToolReported,
            }],
        }
    }

    fn vulnerability_pack() -> EvidencePack {
        EvidencePack {
            schema_version: "local-ai-vet.evidence-pack.v1".to_string(),
            run_id: "test-run".to_string(),
            repo: RawRepo {
                name: "rust-iot-gateway".to_string(),
                language: Some("rust".to_string()),
                commit: None,
                branch: None,
            },
            evidence: vec![
                EvidenceRecord {
                    evidence_id: "vuln:cargo-audit:RUSTSEC-2026-0104:rustls-webpki:0.103.10"
                        .to_string(),
                    run_id: "test-run".to_string(),
                    kind: EvidenceKind::Vulnerability,
                    source: EvidenceSource {
                        file: "cargo-audit.json".to_string(),
                        pointer: Some("/vulnerabilities/list/0".to_string()),
                        sha256: None,
                    },
                    subject: json!({
                        "ecosystem": "cargo",
                        "package": "rustls-webpki",
                        "version": "0.103.10",
                        "advisory_id": "RUSTSEC-2026-0104"
                    }),
                    claim: json!({
                        "related_component_evidence_id": "component:cargo:rustls-webpki:0.103.10"
                    }),
                    confidence: EvidenceConfidence::ToolReported,
                },
                EvidenceRecord {
                    evidence_id: "component:cargo:rustls-webpki:0.103.10".to_string(),
                    run_id: "test-run".to_string(),
                    kind: EvidenceKind::Component,
                    source: EvidenceSource {
                        file: "sbom.cdx.json".to_string(),
                        pointer: Some("/components/0".to_string()),
                        sha256: None,
                    },
                    subject: json!({
                        "ecosystem": "cargo",
                        "name": "rustls-webpki",
                        "version": "0.103.10"
                    }),
                    claim: json!({
                        "component_present": true
                    }),
                    confidence: EvidenceConfidence::ToolReported,
                },
                EvidenceRecord {
                    evidence_id: "provenance:artifact-integrity".to_string(),
                    run_id: "test-run".to_string(),
                    kind: EvidenceKind::Provenance,
                    source: EvidenceSource {
                        file: "artifact-digests.txt".to_string(),
                        pointer: None,
                        sha256: None,
                    },
                    subject: json!({
                        "bundle_id": "test-run"
                    }),
                    claim: json!({
                        "verified": true
                    }),
                    confidence: EvidenceConfidence::DerivedFromTools,
                },
            ],
        }
    }

    fn test_triage(evidence_refs: Vec<&str>) -> AiTriageResult {
        AiTriageResult {
            schema_version: "evidence-triage.ai_triage.v1".to_string(),
            run_id: "test-run".to_string(),
            model: ModelInfo {
                provider: "ollama".to_string(),
                name: "qwen2.5-coder".to_string(),
            },
            evidence_audit: None,
            summary: "summary".to_string(),
            finding_candidates: vec![AiFindingCandidate {
                candidate_id: "candidate-1".to_string(),
                title: "Candidate".to_string(),
                category: "Component".to_string(),
                priority_suggestion: "review".to_string(),
                affected_components: vec!["zip@2.4.2".to_string()],
                evidence_refs: evidence_refs.into_iter().map(str::to_string).collect(),
                why_review_worthy: "why".to_string(),
                iot_relevance: "context".to_string(),
                suggested_human_checks: vec!["check".to_string()],
                uncertainty: "uncertain".to_string(),
                recommended_human_status: "review".to_string(),
            }],
        }
    }

    #[test]
    fn rejects_evidence_id_prefix_in_refs() {
        let err = validate_ai_triage_refs(
            &component_pack(),
            &test_triage(vec!["evidence_id:component:cargo:zip:2.4.2"]),
        )
        .expect_err("prefixed evidence refs should be rejected");

        assert!(err.to_string().contains("unsupported prefix"));
    }

    #[test]
    fn accepts_exact_evidence_id_refs() {
        validate_ai_triage_refs(
            &component_pack(),
            &test_triage(vec!["component:cargo:zip:2.4.2"]),
        )
        .expect("exact evidence refs should be valid");
    }

    #[test]
    fn rejects_provenance_refs_as_finding_evidence() {
        let err = validate_ai_triage_refs(
            &vulnerability_pack(),
            &test_triage(vec!["provenance:artifact-integrity"]),
        )
        .expect_err("provenance refs should be rejected");

        assert!(err.to_string().contains("provenance evidence"));
    }

    #[test]
    fn rejects_candidates_without_vulnerability_refs_when_vulnerabilities_exist() {
        let err = validate_ai_triage_refs(
            &vulnerability_pack(),
            &test_triage(vec!["component:cargo:rustls-webpki:0.103.10"]),
        )
        .expect_err("candidate should reference vulnerability evidence");

        assert!(err.to_string().contains("at least one vulnerability"));
    }

    #[test]
    fn accepts_vulnerability_ref_with_linked_component_context() {
        validate_ai_triage_refs(
            &vulnerability_pack(),
            &test_triage(vec![
                "vuln:cargo-audit:RUSTSEC-2026-0104:rustls-webpki:0.103.10",
                "component:cargo:rustls-webpki:0.103.10",
            ]),
        )
        .expect("vulnerability plus linked component should be valid");
    }
}
