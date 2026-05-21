use crate::evidence::model::EvidencePack;
use crate::triage::candidate::AiTriageResult;

use anyhow::{Result, bail};
use std::collections::HashSet;

pub fn collect_evidence_ids(pack: &EvidencePack) -> HashSet<String> {
    pack.evidence
        .iter()
        .map(|record| record.evidence_id.clone())
        .collect()
}

pub fn validate_ai_triage_refs(pack: &EvidencePack, triage: &AiTriageResult) -> Result<()> {
    let evidence_ids = collect_evidence_ids(pack);

    for candidate in &triage.finding_candidates {
        if candidate.evidence_refs.is_empty() {
            bail!("candidate {} has no evidence_refs", candidate.candidate_id)
        }
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

    fn test_pack() -> EvidencePack {
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

    fn test_triage(evidence_ref: &str) -> AiTriageResult {
        AiTriageResult {
            schema_version: "evidence-triage.ai_triage.v1".to_string(),
            run_id: "test-run".to_string(),
            model: ModelInfo {
                provider: "ollama".to_string(),
                name: "qwen2.5-coder".to_string(),
            },
            summary: "summary".to_string(),
            finding_candidates: vec![AiFindingCandidate {
                candidate_id: "candidate-1".to_string(),
                title: "Candidate".to_string(),
                category: "Component".to_string(),
                priority_suggestion: "review".to_string(),
                affected_components: vec!["zip@2.4.2".to_string()],
                evidence_refs: vec![evidence_ref.to_string()],
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
            &test_pack(),
            &test_triage("evidence_id:component:cargo:zip:2.4.2"),
        )
        .expect_err("prefixed evidence refs should be rejected");

        assert!(err.to_string().contains("unsupported prefix"));
    }

    #[test]
    fn accepts_exact_evidence_id_refs() {
        validate_ai_triage_refs(&test_pack(), &test_triage("component:cargo:zip:2.4.2"))
            .expect("exact evidence refs should be valid");
    }
}
