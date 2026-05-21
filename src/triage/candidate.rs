use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTriageResult {
    pub schema_version: String,
    pub run_id: String,
    pub model: ModelInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_audit: Option<EvidenceAuditSummary>,
    pub summary: String,
    pub finding_candidates: Vec<AiFindingCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub provider: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceAuditSummary {
    pub repo_name: String,
    pub commit: Option<String>,
    pub branch: Option<String>,
    pub git_tree_state: Option<String>,
    pub bundle_id: Option<String>,
    pub generated_at_utc: Option<String>,
    pub artifact_verification: Option<ArtifactVerificationSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactVerificationSummary {
    pub verified: bool,
    pub artifact_count: usize,
    pub digest_file: String,
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
