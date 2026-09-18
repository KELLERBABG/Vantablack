//! Invention §44: Sovereign Cloud (Topology-Enforced Jurisdiction Constraints)
//!
//! A mesh-native cloud fabric where user devices form the storage and compute layer
//! with zero central provider or cloud accounts.
//!
//! Enforces geographic and compliance policies strictly via topological routing constraints:
//! an object tagged with a jurisdiction requirement (e.g. `JurisdictionTag::Eu`) can only
//! be deposited, held, or resolved by endpoints verified to lie within that legal perimeter.

use std::collections::HashMap;

/// Legal / geographic jurisdiction perimeters for data sovereignty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JurisdictionTag {
    Any,
    Eu,
    Us,
    Ch, // Switzerland
    Apac,
}

/// An endpoint device participating in the sovereign cloud mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SovereignDevice {
    pub device_id: String,
    pub jurisdiction: JurisdictionTag,
    pub storage_capacity_bytes: u64,
}

/// A stored sovereign object metadata record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SovereignObject {
    pub object_id: [u8; 32],
    pub required_jurisdiction: JurisdictionTag,
    pub assigned_devices: Vec<String>,
}

/// Sovereign Cloud Fabric coordinating multi-device storage and topological enforcement.
#[derive(Debug, Default)]
pub struct SovereignCloudFabric {
    devices: HashMap<String, SovereignDevice>,
    objects: HashMap<[u8; 32], SovereignObject>,
}

impl SovereignCloudFabric {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an owned device into the sovereign cloud fabric.
    pub fn register_device(&mut self, device: SovereignDevice) {
        self.devices.insert(device.device_id.clone(), device);
    }

    /// Store an object ensuring strict compliance with the required jurisdiction.
    /// Returns Ok(assigned_device_ids) or Err if no compliant devices are available.
    pub fn place_object(
        &mut self,
        object_id: [u8; 32],
        required_jurisdiction: JurisdictionTag,
        replication_factor: usize,
    ) -> Result<Vec<String>, &'static str> {
        // Filter candidate devices by jurisdiction
        let mut candidates: Vec<String> = self
            .devices
            .values()
            .filter(|d| {
                required_jurisdiction == JurisdictionTag::Any
                    || d.jurisdiction == required_jurisdiction
            })
            .map(|d| d.device_id.clone())
            .collect();

        if candidates.len() < replication_factor {
            return Err("insufficient compliant endpoints meeting jurisdiction constraint");
        }

        candidates.truncate(replication_factor);
        self.objects.insert(
            object_id,
            SovereignObject {
                object_id,
                required_jurisdiction,
                assigned_devices: candidates.clone(),
            },
        );

        Ok(candidates)
    }

    /// Verify whether all current holders of an object strictly satisfy its legal jurisdiction.
    pub fn verify_object_compliance(&self, object_id: &[u8; 32]) -> bool {
        if let Some(obj) = self.objects.get(object_id) {
            if obj.required_jurisdiction == JurisdictionTag::Any {
                return true;
            }
            obj.assigned_devices.iter().all(|dev_id| {
                if let Some(dev) = self.devices.get(dev_id) {
                    dev.jurisdiction == obj.required_jurisdiction
                } else {
                    false
                }
            })
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sovereign_cloud_jurisdiction_constraint_enforcement() {
        let mut fabric = SovereignCloudFabric::new();

        // Register 4 owned devices: 2 EU, 1 US, 1 CH
        fabric.register_device(SovereignDevice {
            device_id: "laptop_berlin".into(),
            jurisdiction: JurisdictionTag::Eu,
            storage_capacity_bytes: 500_000_000,
        });
        fabric.register_device(SovereignDevice {
            device_id: "nas_paris".into(),
            jurisdiction: JurisdictionTag::Eu,
            storage_capacity_bytes: 2_000_000_000,
        });
        fabric.register_device(SovereignDevice {
            device_id: "server_us_east".into(),
            jurisdiction: JurisdictionTag::Us,
            storage_capacity_bytes: 1_000_000_000,
        });
        fabric.register_device(SovereignDevice {
            device_id: "node_zurich".into(),
            jurisdiction: JurisdictionTag::Ch,
            storage_capacity_bytes: 800_000_000,
        });

        let eu_object_id = [0xEEu8; 32];

        // 1. Place EU-only object with replication 2
        let placement = fabric
            .place_object(eu_object_id, JurisdictionTag::Eu, 2)
            .expect("EU placement succeeds");
        assert_eq!(placement.len(), 2);
        assert!(placement.contains(&"laptop_berlin".to_string()));
        assert!(placement.contains(&"nas_paris".to_string()));
        assert!(!placement.contains(&"server_us_east".to_string()));

        // 2. Invariant: Must strictly comply
        assert!(fabric.verify_object_compliance(&eu_object_id));

        // 3. Requesting replication factor 3 for EU fails because only 2 EU endpoints exist
        let eu_obj_fail = [0x55u8; 32];
        let err = fabric.place_object(eu_obj_fail, JurisdictionTag::Eu, 3);
        assert!(
            err.is_err(),
            "Must reject rather than spill into non-EU nodes"
        );
    }
}
