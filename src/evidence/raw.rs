use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvidencePack {
    pub schema_version: String,
    pub run_id: String,
    pub repo: RawRepo,

    #[serde(default)]
    pub system_context: serde_json::Value,

    #[serde(default)]
    pub baseline_diff: serde_json::Value,

    #[serde(default)]
    pub scanner_findings: Vec<serde_json::Value>,

    #[serde(default)]
    pub sbom_components: Vec<serde_json::Value>,

    #[serde(default)]
    pub audit_engine_findings: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawRepo {
    pub name: String,

    #[serde(default)]
    pub language: Option<String>,

    #[serde(default)]
    pub commit: Option<String>,

    #[serde(default)]
    pub branch: Option<String>,
}
