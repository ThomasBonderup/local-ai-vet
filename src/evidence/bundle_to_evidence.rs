use std::path::Path;

use crate::{adapters::traits::BundleContext, evidence::default_adapters};

pub fn convert_gateway_release_bundle(bundle_dir: &Path) -> anyhow::Result<()> {
    let ctx = BundleContext {
        run_id: infer_run_id(&bundle_dir),
        repo_name: Some("rust-iot-gateway".to_string()),
        bundle_dir: bundle_dir.clone(),
    };

    let adapters = default_adapters();
    // let files = discover_bundle_files(&bundle_dir).context("failed to discover bundle files")?;

    // for file in files {
    // for adapter in &adapters {
    //     if adapter.supports(&file) {
    //       let mut parsed = adapter.parse(&file, &ctx).context("failed to parse evidence file")?;
    //       records.extend(&mut parsed);
    //     }
    // }
    Ok(())
}

fn infer_run_id(bundle_dir: &Path) -> String {
    bundle_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown-run")
        .to_string()
}
