use crate::evidence::model::EvidenceRecord;
use anyhow::Result;
use std::path::Path;

pub struct BundleContext {
    pub run_id: String,
    pub repo_name: String,
    #[allow(dead_code)]
    pub bundle_dir: std::path::PathBuf,
}

pub trait EvidenceAdapter {
    fn name(&self) -> &'static str;

    fn supports(&self, path: &Path) -> bool;

    fn parse(&self, path: &Path, ctx: &BundleContext) -> Result<Vec<EvidenceRecord>>;
}
