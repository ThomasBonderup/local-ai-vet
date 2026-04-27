use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTriageResult {
    pub schema_version: String,
    pub run_id: String,
    pub model: ModelInfo,
    pub summary: String,
    pub finding_candidates: Vec<AiFindingCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub provider: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiFindingCandidate {
    pub candidate_id: String,
    pub title: String,
    pub category: String,
    pub priority_suggestion: String,
    pub affected_components: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub why_review_worthy: String,
    pub iot_relevance: String,
    pub suggested_human_checks: Vec<String>,
    pub uncertainty: String,
    pub recommended_human_status: String,
}
