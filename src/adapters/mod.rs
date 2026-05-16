pub mod cargo_audit;
pub mod cyclone_dx;
pub mod traits;

use cargo_audit::CargoAuditAdapter;
use traits::EvidenceAdapter;

use crate::adapters::cyclone_dx::CycloneDxAdapter;

pub fn default_adapters() -> Vec<Box<dyn EvidenceAdapter>> {
    vec![Box::new(CargoAuditAdapter), Box::new(CycloneDxAdapter)]
}
