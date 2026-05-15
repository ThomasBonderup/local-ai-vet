use crate::evidence::raw::RawRepo;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub run_id: String,
    pub kind: EvidenceKind,
    pub source: EvidenceSource,
    pub subject: serde_json::Value,
    pub claim: serde_json::Value,
    pub confidence: EvidenceConfidence,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum EvidenceKind {
    ScannerFinding,
    SbomComponent,
    AuditEngineFinding,
    BaselineDiff,
    SystemContext,
    Vulnerability,
    Component,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EvidenceSource {
    pub file: String,
    pub pointer: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    ToolReported,
    DerivedFromTools,
    HumanVerified,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvidencePack {
    pub schema_version: String,
    pub run_id: String,
    pub repo: RawRepo,
    pub evidence: Vec<EvidenceRecord>,
}
