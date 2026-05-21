use crate::evidence::model::EvidencePack;
use crate::llm::prompt::{build_triage_prompt, triage_reference_ids};
use crate::triage::candidate::{
    AiTriageResult, ArtifactVerificationSummary, EvidenceAuditSummary, ModelInfo,
};
use anyhow::{Result, anyhow};
use reqwest::Client;
use serde_json::json;

pub struct OllamaClient {
    base_url: String,
    model: String,
    http: Client,
}

impl OllamaClient {
    pub fn new(base_url: String, model: String) -> Self {
        Self {
            base_url,
            model,
            http: Client::new(),
        }
    }

    pub async fn triage(&self, pack: &EvidencePack) -> Result<AiTriageResult> {
        let prompt = build_triage_prompt(pack)?;
        let evidence_ids = triage_reference_ids(pack);
        let evidence_ref_item_schema = if evidence_ids.is_empty() {
            json!({ "type": "string" })
        } else {
            json!({ "type": "string", "enum": evidence_ids })
        };

        let schema = json!({
            "type": "object",
            "properties": {
                "summary": { "type": "string" },
                "finding_candidates": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "candidate_id": { "type": "string" },
                            "title": { "type": "string" },
                            "category": { "type": "string" },
                            "priority_suggestion": { "type": "string" },
                            "affected_components": {
                                "type": "array",
                                "items": { "type": "string" }
                            },
                            "evidence_refs": {
                                "type": "array",
                                "items": evidence_ref_item_schema
                            },
                            "why_review_worthy": { "type": "string" },
                            "iot_relevance": { "type": "string" },
                            "suggested_human_checks": {
                                "type": "array",
                                "items": { "type": "string" }
                            },
                            "uncertainty": { "type": "string" },
                            "recommended_human_status": { "type": "string" }
                        },
                        "required": [
                            "candidate_id",
                            "title",
                            "category",
                            "priority_suggestion",
                            "affected_components",
                            "evidence_refs",
                            "why_review_worthy",
                            "iot_relevance",
                            "suggested_human_checks",
                            "uncertainty",
                            "recommended_human_status"
                        ]
                    }
                }
            },
            "required": ["summary", "finding_candidates"]
        });

        let body = json!({
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "format": schema,
            "stream": false,
            "options": {
                "temperature": 0.1
            }
        });

        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));

        let response: serde_json::Value = self
            .http
            .post(url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let content = response
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| anyhow!("missing message.content in Ollama response"))?;

        let partial: serde_json::Value = serde_json::from_str(content)?;

        let result = AiTriageResult {
            schema_version: "evidence-triage.ai_triage.v1".to_string(),
            run_id: pack.run_id.clone(),
            model: ModelInfo {
                provider: "ollama".to_string(),
                name: self.model.clone(),
            },
            evidence_audit: build_evidence_audit_summary(pack),
            summary: partial
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            finding_candidates: serde_json::from_value(
                partial
                    .get("finding_candidates")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            )?,
        };

        Ok(result)
    }
}

fn build_evidence_audit_summary(pack: &EvidencePack) -> Option<EvidenceAuditSummary> {
    let source_claim = pack
        .evidence
        .iter()
        .find(|record| record.evidence_id == "provenance:bundle-source")
        .map(|record| &record.claim);
    let integrity_claim = pack
        .evidence
        .iter()
        .find(|record| record.evidence_id == "provenance:artifact-integrity")
        .map(|record| &record.claim);
    let source = source_claim
        .and_then(|claim| claim.get("source"))
        .and_then(|source| source.as_object());

    let manifest = source_claim
        .and_then(|claim| claim.get("manifest"))
        .and_then(|manifest| manifest.as_object());

    let git_tree_state = source
        .and_then(|source| source.get("git_tree_state"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            manifest
                .and_then(|manifest| manifest.get("git_tree_state"))
                .and_then(|v| v.as_str())
        })
        .map(str::to_string);

    let bundle_source = pack
        .evidence
        .iter()
        .find(|record| record.evidence_id == "provenance:bundle-source");

    let bundle_id = bundle_source
        .and_then(|record| record.subject.get("bundle_id"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let generated_at_utc = bundle_source
        .and_then(|record| record.subject.get("generated_at_utc"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let artifact_verification = integrity_claim.map(|claim| ArtifactVerificationSummary {
        verified: claim
            .get("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        artifact_count: claim
            .get("artifacts")
            .and_then(|v| v.as_array())
            .map(|artifacts| artifacts.len())
            .unwrap_or(0),
        digest_file: claim
            .get("digest_file")
            .and_then(|v| v.as_str())
            .unwrap_or("artifact-digests.txt")
            .to_string(),
    });

    if source_claim.is_none() && integrity_claim.is_none() {
        return None;
    }

    Some(EvidenceAuditSummary {
        repo_name: pack.repo.name.clone(),
        commit: pack.repo.commit.clone(),
        branch: pack.repo.branch.clone(),
        git_tree_state,
        bundle_id,
        generated_at_utc,
        artifact_verification,
    })
}
