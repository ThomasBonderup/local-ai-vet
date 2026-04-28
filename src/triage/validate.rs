use crate::evidence::raw::RawEvidencePack;
use crate::triage::candidate::AiTriageResult;

use anyhow::{Result, bail};
use std::collections::HashSet;

pub fn collect_evidence_ids(pack: &RawEvidencePack) -> HashSet<String> {
    let mut ids = HashSet::new();

    for item in &pack.scanner_findings {
        if let Some(id) = item.get("evidence_id").and_then(|v| v.as_str()) {
            ids.insert(id.to_string());
        }
    }

    for item in &pack.sbom_components {
        if let Some(id) = item.get("evidence_id").and_then(|v| v.as_str()) {
            ids.insert(id.to_string());
        }
    }

    for item in &pack.audit_engine_findings {
        if let Some(id) = item.get("evidence_id").and_then(|v| v.as_str()) {
            ids.insert(id.to_string());
        }
    }

    collect_ids_from_value(&pack.baseline_diff, &mut ids);

    ids
}

fn collect_ids_from_value(value: &serde_json::Value, ids: &mut HashSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(id) = map.get("evidence_id").and_then(|v| v.as_str()) {
                ids.insert(id.to_string());
            }

            for value in map.values() {
                collect_ids_from_value(value, ids);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_ids_from_value(item, ids);
            }
        }
        _ => {}
    }
}

pub fn validate_ai_triage_refs(pack: &RawEvidencePack, triage: &AiTriageResult) -> Result<()> {
    let evidence_ids = collect_evidence_ids(pack);

    for candidate in &triage.finding_candidates {
        if candidate.evidence_refs.is_empty() {
            bail!("candidate {} has no evidence_refs", candidate.candidate_id)
        }
        for evidence_ref in &candidate.evidence_refs {
            if !evidence_ids.contains(evidence_ref) {
                bail!(
                    "candiate {} references unkown evidence id: {}",
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
