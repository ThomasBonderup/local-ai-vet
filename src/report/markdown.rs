use crate::triage::candidate::{AiFindingCandidate, AiTriageResult, EvidenceAuditSummary};

pub fn render_markdown_report(triage: &AiTriageResult) -> String {
    let mut md = String::new();

    md.push_str("# AI-Assisted Security Triage Review\n\n");

    md.push_str(&format!("Run: `{}`  \n", triage.run_id));
    md.push_str(&format!("Model: `{}`  \n", triage.model.name));
    md.push_str(&format!("Provider: `{}`\n\n", triage.model.provider));

    if let Some(audit) = &triage.evidence_audit {
        render_evidence_audit(&mut md, audit);
    }

    md.push_str("## Summary\n\n");
    md.push_str(&triage.summary);
    md.push_str("\n\n");

    if triage.finding_candidates.is_empty() {
        md.push_str("## Finding Candidates\n\n");
        md.push_str("No AI-generated finding candidates were produced for this run.\n");
        return md;
    }

    md.push_str("## Finding Candidates\n\n");

    for (index, candidate) in triage.finding_candidates.iter().enumerate() {
        render_candidate(&mut md, index + 1, candidate);
    }

    md
}

fn render_evidence_audit(md: &mut String, audit: &EvidenceAuditSummary) {
    md.push_str("## Evidence Provenance\n\n");
    md.push_str(&format!("Repository: `{}`  \n", audit.repo_name));

    if let Some(bundle_id) = &audit.bundle_id {
        md.push_str(&format!("Bundle: `{bundle_id}`  \n"));
    }
    if let Some(generated_at_utc) = &audit.generated_at_utc {
        md.push_str(&format!("Generated: `{generated_at_utc}`  \n"));
    }
    if let Some(commit) = &audit.commit {
        md.push_str(&format!("Commit: `{commit}`  \n"));
    }
    if let Some(branch) = &audit.branch {
        md.push_str(&format!("Branch: `{branch}`  \n"));
    }
    if let Some(git_tree_state) = &audit.git_tree_state {
        md.push_str(&format!("Tree state: **{git_tree_state}**  \n"));
    }
    if let Some(verification) = &audit.artifact_verification {
        let status = if verification.verified {
            "verified"
        } else {
            "not verified"
        };
        md.push_str(&format!(
            "Artifact integrity: **{}** ({} artifacts via `{}`)  \n",
            status, verification.artifact_count, verification.digest_file
        ));
    }

    md.push('\n');
}

fn render_candidate(md: &mut String, index: usize, candidate: &AiFindingCandidate) {
    md.push_str(&format!("## Candidate {}: {}\n\n", index, candidate.title));

    md.push_str(&format!("Candidate ID: `{}`  \n", candidate.candidate_id));
    md.push_str(&format!("Category: `{}`  \n", candidate.category));
    md.push_str(&format!(
        "Priority suggestion: **{}**  \n",
        candidate.priority_suggestion
    ));
    md.push_str(&format!(
        "Recommended human status: **{}**\n\n",
        candidate.recommended_human_status
    ));

    md.push_str("### Affected components\n\n");

    if candidate.affected_components.is_empty() {
        md.push_str("- None supplied\n\n");
    } else {
        for component in &candidate.affected_components {
            md.push_str(&format!("- `{}`\n", component));
        }
        md.push('\n');
    }

    md.push_str("### Evidence\n\n");

    if candidate.evidence_refs.is_empty() {
        md.push_str("- No evidence references supplied\n\n");
    } else {
        for evidence_ref in &candidate.evidence_refs {
            md.push_str(&format!("- `{}`\n", evidence_ref));
        }
        md.push('\n');
    }

    md.push_str("### Why review-worthy\n\n");
    md.push_str(&candidate.why_review_worthy);
    md.push_str("\n\n");

    md.push_str("### IoT relevance\n\n");
    md.push_str(&candidate.iot_relevance);
    md.push_str("\n\n");

    md.push_str("### Suggested human checks\n\n");

    if candidate.suggested_human_checks.is_empty() {
        md.push_str("- No suggested checks supplied\n\n");
    } else {
        for check in &candidate.suggested_human_checks {
            md.push_str(&format!("- {}\n", check));
        }
        md.push('\n');
    }

    md.push_str("### Uncertainty\n\n");
    md.push_str(&candidate.uncertainty);
    md.push_str("\n\n");

    md.push_str("### Human decision\n\n");
    md.push_str("- [ ] Approved finding\n");
    md.push_str("- [ ] False positive\n");
    md.push_str("- [ ] Accepted risk\n");
    md.push_str("- [ ] Needs more evidence\n");
    md.push_str("- [ ] Needs remediation\n\n");

    md.push_str("### Reviewer notes\n\n");
    md.push_str("_Add notes here._\n\n");

    md.push_str("---\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triage::candidate::{
        AiFindingCandidate, ArtifactVerificationSummary, EvidenceAuditSummary, ModelInfo,
    };

    #[test]
    fn renders_evidence_provenance_when_audit_summary_exists() {
        let triage = AiTriageResult {
            schema_version: "evidence-triage.ai_triage.v1".to_string(),
            run_id: "test-run".to_string(),
            model: ModelInfo {
                provider: "ollama".to_string(),
                name: "qwen2.5-coder".to_string(),
            },
            evidence_audit: Some(EvidenceAuditSummary {
                repo_name: "rust-iot-gateway".to_string(),
                commit: Some("abc123".to_string()),
                branch: Some("main".to_string()),
                git_tree_state: Some("clean".to_string()),
                bundle_id: Some("test-bundle".to_string()),
                generated_at_utc: Some("20260512T130225Z".to_string()),
                artifact_verification: Some(ArtifactVerificationSummary {
                    verified: true,
                    artifact_count: 4,
                    digest_file: "artifact-digests.txt".to_string(),
                }),
            }),
            summary: "summary".to_string(),
            finding_candidates: vec![AiFindingCandidate {
                candidate_id: "candidate-1".to_string(),
                title: "Candidate".to_string(),
                category: "Dependency".to_string(),
                priority_suggestion: "Medium".to_string(),
                affected_components: vec![],
                evidence_refs: vec![],
                why_review_worthy: "why".to_string(),
                iot_relevance: "iot".to_string(),
                suggested_human_checks: vec![],
                uncertainty: "uncertain".to_string(),
                recommended_human_status: "Review".to_string(),
            }],
        };

        let markdown = render_markdown_report(&triage);

        assert!(markdown.contains("## Evidence Provenance"));
        assert!(markdown.contains("Commit: `abc123`"));
        assert!(
            markdown.contains(
                "Artifact integrity: **verified** (4 artifacts via `artifact-digests.txt`)"
            )
        );
    }
}
