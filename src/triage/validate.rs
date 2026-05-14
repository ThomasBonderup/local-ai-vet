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
