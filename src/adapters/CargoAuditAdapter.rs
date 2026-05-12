pub struct CargoAuditAdapter;

impl EvidenceAdapter for CargoAuditAdapter {
    fn name(&self) -> &'static str {
        "cargo-audit"
    }

    fn supports(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == "cargo-audit.json")
            .unwrap_or(false)
    }

    fn parse(&self, path: &Path, ctx: &BundleContext) -> Result<Vec<EvidenceRecord>> {
        let mut records = Vec::new();

        Ok(records)
    }
}
