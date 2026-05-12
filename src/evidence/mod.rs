pub mod bundle_to_evidence;
pub mod model;
pub mod raw;

use crate::adapters::CargoAuditAdapter;
use crate::adapters::traits::EvidenceAdapter;

pub fn default_adapters() -> Vec<Box<dyn EvidenceAdapter>> {
    vec![Box::new(CargoAuditAdapter)]
}
