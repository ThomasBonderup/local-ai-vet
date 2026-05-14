use anyhow::{Context, Result, bail};
use std::fs;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

pub fn discover_bundle_files(bundle_dir: &Path) -> Result<Vec<PathBuf>> {
    if !bundle_dir.exists() {
        bail!("Bundle directory does not exist: {}", bundle_dir.display());
    }

    if !bundle_dir.is_dir() {
        bail!(
            "Bundle directory is not a directory: {}",
            bundle_dir.display()
        );
    }

    let expected_files: HashSet<&str> = HashSet::from([
        "sbom.cdx.json",
        "cargo-audit.json",
        "cargo-audit.stderr",
        "cargo-metadata.json",
        "tool-versions.txt",
        "source-tree-status.txt",
        "manifest.json",
        "provenance.json",
        "artifact-digests.txt",
    ]);

    let mut files = Vec::new();

    for entry in fs::read_dir(bundle_dir)
        .with_context(|| format!("failed to read bundle directory: {}", bundle_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if !entry.metadata()?.is_file() {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        if expected_files.contains(file_name) {
            files.push(path);
        }
    }
    files.sort();

    Ok(files)
}
