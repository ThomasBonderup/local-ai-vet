use crate::triage::candidate::{AiFindingCandidate, AiTriageResult};

pub fn render_markdown_report(triage: &AiTriageResult) -> String {
    let mut md = String::new();

    md.push_str("# AI-Assisted Security Triage Review\n\n");

    md.push_str(&format!("Run: `{}`  \n", triage.run_id));
    md.push_str(&format!("Model: `{}`  \n", triage.model.name));
    md.push_str(&format!("Provider: `{}`\n\n", triage.model.provider));

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
