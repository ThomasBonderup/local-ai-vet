use anyhow::{Context, Result};
use std::path::Path;

use crate::evidence::model::EvidencePack;

pub fn write_evidence_pack(pack: &EvidencePack, output: &Path) -> Result<()> {
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }

    let json = serde_json::to_string_pretty(pack).context("failed to serialize ")?;

    std::fs::write(output, json)
        .with_context(|| format!("failed to write evidence pack to {}", output.display()))?;

    Ok(())
}
