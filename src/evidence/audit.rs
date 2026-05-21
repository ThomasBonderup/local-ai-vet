use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use crate::{
    adapters::traits::BundleContext,
    evidence::{
        model::{EvidenceConfidence, EvidenceKind, EvidenceRecord, EvidenceSource},
        raw::RawRepo,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDigest {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactVerificationStatus {
    Matched,
    Missing,
    Mismatched,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactVerification {
    pub path: String,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub status: ArtifactVerificationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleVerificationResult {
    pub digest_file: String,
    pub verified: bool,
    pub artifacts: Vec<ArtifactVerification>,
}

#[derive(Debug, Clone, Deserialize)]
struct BundleManifest {
    #[serde(default)]
    generated_at_utc: Option<String>,
    #[serde(default)]
    bundle_id: Option<String>,
    #[serde(default)]
    git_head: Option<String>,
    #[serde(default)]
    git_branch: Option<String>,
    #[serde(default)]
    git_tree_state: Option<String>,
    #[serde(default)]
    package: Option<ManifestPackage>,
    #[serde(default)]
    audit: Option<ManifestAudit>,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestPackage {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    cargo_lock_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestAudit {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    exit_code: Option<i64>,
    #[serde(default)]
    advisory_db_head: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct BundleProvenance {
    #[serde(default)]
    generated_at_utc: Option<String>,
    #[serde(default)]
    bundle_id: Option<String>,
    #[serde(default)]
    source: Option<ProvenanceSource>,
}

#[derive(Debug, Clone, Deserialize)]
struct ProvenanceSource {
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    package_name: Option<String>,
    #[serde(default)]
    package_version: Option<String>,
    #[serde(default)]
    git_head: Option<String>,
    #[serde(default)]
    git_branch: Option<String>,
    #[serde(default)]
    git_tree_state: Option<String>,
    #[serde(default)]
    cargo_lock_sha256: Option<String>,
}

pub fn artifact_digest_path(bundle_dir: &Path) -> PathBuf {
    bundle_dir.join("artifact-digests.txt")
}

pub fn read_artifact_digests(bundle_dir: &Path) -> Result<Option<Vec<ArtifactDigest>>> {
    let path = artifact_digest_path(bundle_dir);
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read artifact digest file: {}", path.display()))?;
    parse_artifact_digests(&raw).map(Some)
}

pub fn parse_artifact_digests(raw: &str) -> Result<Vec<ArtifactDigest>> {
    let mut digests = Vec::new();

    for (line_idx, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let sha256 = parts
            .next()
            .ok_or_else(|| anyhow!("missing digest on line {}", line_idx + 1))?;
        let path = parts
            .next()
            .ok_or_else(|| anyhow!("missing artifact path on line {}", line_idx + 1))?;

        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("invalid SHA-256 digest on line {}", line_idx + 1);
        }
        if parts.next().is_some() {
            bail!("unexpected extra fields on digest line {}", line_idx + 1);
        }

        digests.push(ArtifactDigest {
            path: path.to_string(),
            sha256: sha256.to_ascii_lowercase(),
        });
    }

    Ok(digests)
}

pub fn artifact_digest_map(bundle_dir: &Path) -> Result<BTreeMap<String, String>> {
    Ok(read_artifact_digests(bundle_dir)?
        .unwrap_or_default()
        .into_iter()
        .map(|digest| (digest.path, digest.sha256))
        .collect())
}

pub fn verify_bundle(bundle_dir: &Path) -> Result<Option<BundleVerificationResult>> {
    let Some(digests) = read_artifact_digests(bundle_dir)? else {
        return Ok(None);
    };

    let artifacts = digests
        .into_iter()
        .map(|digest| {
            let artifact_path = bundle_dir.join(&digest.path);
            let actual_sha256 = if artifact_path.exists() {
                Some(sha256_file(&artifact_path)?)
            } else {
                None
            };
            let status = match actual_sha256.as_deref() {
                Some(actual) if actual == digest.sha256 => ArtifactVerificationStatus::Matched,
                Some(_) => ArtifactVerificationStatus::Mismatched,
                None => ArtifactVerificationStatus::Missing,
            };

            Ok(ArtifactVerification {
                path: digest.path,
                expected_sha256: digest.sha256,
                actual_sha256,
                status,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let verified = artifacts
        .iter()
        .all(|artifact| artifact.status == ArtifactVerificationStatus::Matched);

    Ok(Some(BundleVerificationResult {
        digest_file: "artifact-digests.txt".to_string(),
        verified,
        artifacts,
    }))
}

pub fn require_verified_bundle(bundle_dir: &Path) -> Result<BundleVerificationResult> {
    let result = verify_bundle(bundle_dir)?.ok_or_else(|| {
        anyhow!(
            "bundle has no artifact-digests.txt; cannot verify artifact integrity: {}",
            bundle_dir.display()
        )
    })?;

    if !result.verified {
        let failures: Vec<_> = result
            .artifacts
            .iter()
            .filter(|artifact| artifact.status != ArtifactVerificationStatus::Matched)
            .map(|artifact| format!("{} ({:?})", artifact.path, artifact.status))
            .collect();
        bail!(
            "bundle artifact verification failed: {}",
            failures.join(", ")
        );
    }

    Ok(result)
}

pub fn add_source_digests(records: &mut [EvidenceRecord], digests: &BTreeMap<String, String>) {
    for record in records {
        if let Some(sha256) = digests.get(&record.source.file) {
            record.source.sha256 = Some(sha256.clone());
        }
    }
}

pub fn repo_from_bundle_metadata(bundle_dir: &Path, fallback_name: &str) -> Result<RawRepo> {
    let manifest = read_manifest(bundle_dir)?;
    let provenance = read_provenance(bundle_dir)?;
    let source = provenance.as_ref().and_then(|p| p.source.as_ref());

    Ok(RawRepo {
        name: source
            .and_then(|s| s.repository.clone())
            .or_else(|| {
                manifest
                    .as_ref()
                    .and_then(|m| m.package.as_ref())
                    .and_then(|p| p.name.clone())
            })
            .unwrap_or_else(|| fallback_name.to_string()),
        language: Some("rust".to_string()),
        commit: source
            .and_then(|s| s.git_head.clone())
            .or_else(|| manifest.as_ref().and_then(|m| m.git_head.clone())),
        branch: source
            .and_then(|s| s.git_branch.clone())
            .or_else(|| manifest.as_ref().and_then(|m| m.git_branch.clone())),
    })
}

pub fn provenance_records(
    bundle_dir: &Path,
    ctx: &BundleContext,
    verification: Option<&BundleVerificationResult>,
) -> Result<Vec<EvidenceRecord>> {
    let manifest = read_json_value(bundle_dir, "manifest.json")?;
    let provenance = read_json_value(bundle_dir, "provenance.json")?;
    let typed_manifest = read_manifest(bundle_dir)?;
    let typed_provenance = read_provenance(bundle_dir)?;

    let mut records = Vec::new();

    if manifest.is_some() || provenance.is_some() {
        records.push(EvidenceRecord {
            evidence_id: "provenance:bundle-source".to_string(),
            run_id: ctx.run_id.clone(),
            kind: EvidenceKind::Provenance,
            source: EvidenceSource {
                file: "provenance.json".to_string(),
                pointer: Some("/source".to_string()),
                sha256: None,
            },
            subject: json!({
                "bundle_id": typed_provenance
                    .as_ref()
                    .and_then(|p| p.bundle_id.as_deref())
                    .or_else(|| typed_manifest.as_ref().and_then(|m| m.bundle_id.as_deref())),
                "generated_at_utc": typed_provenance
                    .as_ref()
                    .and_then(|p| p.generated_at_utc.as_deref())
                    .or_else(|| typed_manifest.as_ref().and_then(|m| m.generated_at_utc.as_deref())),
                "repository": typed_provenance
                    .as_ref()
                    .and_then(|p| p.source.as_ref())
                    .and_then(|s| s.repository.as_deref()),
            }),
            claim: json!({
                "source": typed_provenance.as_ref().and_then(|p| p.source.as_ref()).map(|source| {
                    json!({
                        "repository": source.repository,
                        "package_name": source.package_name,
                        "package_version": source.package_version,
                        "git_head": source.git_head,
                        "git_branch": source.git_branch,
                        "git_tree_state": source.git_tree_state,
                        "cargo_lock_sha256": source.cargo_lock_sha256,
                    })
                }),
                "manifest": typed_manifest.as_ref().map(|manifest| {
                    json!({
                        "git_head": manifest.git_head,
                        "git_branch": manifest.git_branch,
                        "git_tree_state": manifest.git_tree_state,
                        "package": manifest.package.as_ref().map(|package| json!({
                            "name": package.name,
                            "version": package.version,
                            "cargo_lock_sha256": package.cargo_lock_sha256,
                        })),
                    })
                }),
                "raw_manifest_present": manifest.is_some(),
                "raw_provenance_present": provenance.is_some(),
            }),
            confidence: EvidenceConfidence::ToolReported,
        });
    }

    if let Some(typed_manifest) = typed_manifest.as_ref() {
        records.push(EvidenceRecord {
            evidence_id: "provenance:audit-run".to_string(),
            run_id: ctx.run_id.clone(),
            kind: EvidenceKind::Provenance,
            source: EvidenceSource {
                file: "manifest.json".to_string(),
                pointer: Some("/audit".to_string()),
                sha256: None,
            },
            subject: json!({
                "bundle_id": typed_manifest.bundle_id,
                "generated_at_utc": typed_manifest.generated_at_utc,
            }),
            claim: json!({
                "audit": typed_manifest.audit.as_ref().map(|audit| json!({
                    "command": audit.command,
                    "exit_code": audit.exit_code,
                    "advisory_db_head": audit.advisory_db_head,
                })),
            }),
            confidence: EvidenceConfidence::ToolReported,
        });
    }

    if let Some(verification) = verification {
        records.push(EvidenceRecord {
            evidence_id: "provenance:artifact-integrity".to_string(),
            run_id: ctx.run_id.clone(),
            kind: EvidenceKind::Provenance,
            source: EvidenceSource {
                file: verification.digest_file.clone(),
                pointer: None,
                sha256: None,
            },
            subject: json!({
                "bundle_id": ctx.run_id,
            }),
            claim: serde_json::to_value(verification)
                .context("failed to serialize bundle verification result")?,
            confidence: EvidenceConfidence::DerivedFromTools,
        });
    }

    Ok(records)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open file: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read file: {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn read_manifest(bundle_dir: &Path) -> Result<Option<BundleManifest>> {
    read_json(bundle_dir, "manifest.json")
}

fn read_provenance(bundle_dir: &Path) -> Result<Option<BundleProvenance>> {
    read_json(bundle_dir, "provenance.json")
}

fn read_json<T>(bundle_dir: &Path, file_name: &str) -> Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let path = bundle_dir.join(file_name);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read bundle metadata: {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse bundle metadata: {}", path.display()))
        .map(Some)
}

fn read_json_value(bundle_dir: &Path, file_name: &str) -> Result<Option<Value>> {
    read_json(bundle_dir, file_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_bundle() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after UNIX epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("local-ai-vet-audit-{unique}"));
        fs::create_dir_all(&dir).expect("failed to create temp bundle");
        dir
    }

    #[test]
    fn parses_artifact_digest_lines() {
        let digests = parse_artifact_digests(
            "bb799a8aa000e182b0ec95bfc7bcc86a34757721fd67227ee9cf1162efcba0de  sbom.cdx.json\n",
        )
        .expect("digest file should parse");

        assert_eq!(
            digests,
            vec![ArtifactDigest {
                path: "sbom.cdx.json".to_string(),
                sha256: "bb799a8aa000e182b0ec95bfc7bcc86a34757721fd67227ee9cf1162efcba0de"
                    .to_string(),
            }]
        );
    }

    #[test]
    fn verifies_matching_artifact_digest() {
        let dir = temp_bundle();
        fs::write(dir.join("artifact.txt"), "trusted evidence").expect("failed to write artifact");
        fs::write(
            dir.join("artifact-digests.txt"),
            "1ed1d397965e1052a9b4505c38f7c25d6629ad86b3570488e2ff1ad07913f802  artifact.txt\n",
        )
        .expect("failed to write digest file");

        let verification = verify_bundle(&dir)
            .expect("verification should run")
            .expect("digest metadata should exist");

        assert!(verification.verified);
        assert_eq!(
            verification.artifacts[0].status,
            ArtifactVerificationStatus::Matched
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reports_mismatched_artifact_digest() {
        let dir = temp_bundle();
        fs::write(dir.join("artifact.txt"), "tampered").expect("failed to write artifact");
        fs::write(
            dir.join("artifact-digests.txt"),
            "40c4ec93b709748606a32025846fbb3de6d5e3d466982c6acc0d08e1512bf1e0  artifact.txt\n",
        )
        .expect("failed to write digest file");

        let verification = verify_bundle(&dir)
            .expect("verification should run")
            .expect("digest metadata should exist");

        assert!(!verification.verified);
        assert_eq!(
            verification.artifacts[0].status,
            ArtifactVerificationStatus::Mismatched
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reports_missing_artifact_digest() {
        let dir = temp_bundle();
        fs::write(
            dir.join("artifact-digests.txt"),
            "40c4ec93b709748606a32025846fbb3de6d5e3d466982c6acc0d08e1512bf1e0  missing.txt\n",
        )
        .expect("failed to write digest file");

        let verification = verify_bundle(&dir)
            .expect("verification should run")
            .expect("digest metadata should exist");

        assert!(!verification.verified);
        assert_eq!(
            verification.artifacts[0].status,
            ArtifactVerificationStatus::Missing
        );

        fs::remove_dir_all(&dir).ok();
    }
}
