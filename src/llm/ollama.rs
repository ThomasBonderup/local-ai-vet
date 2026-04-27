use crate::evidence::raw::RawEvidencePack;
use crate::llm::prompt::build_triage_prompt;
use crate::triage::candidate::{AiTriageResult, ModelInfo};
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

    pub async fn triage(&self, pack: &RawEvidencePack) -> Result<AiTriageResult> {
        let prompt = build_triage_prompt(pack)?;

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
                                "items": { "type": "string" }
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
