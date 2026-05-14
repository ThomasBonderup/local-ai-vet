pub mod cargo_audit_adapter;
pub mod traits;

use cargo_audit_adapter::CargoAuditAdapter;
use traits::EvidenceAdapter;

pub fn default_adapters() -> Vec<Box<dyn EvidenceAdapter>> {
    vec![Box::new(CargoAuditAdapter)]
}
