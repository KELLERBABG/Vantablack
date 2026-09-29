use abos_common::error::Result;
use abos_common::types::Bundle;
use sled::Db;

/// Persistent DTN bundle store backed by sled.
///
/// Adds three behaviours beyond the raw key/value wrapper:
/// - **Dedup on insert**: re-storing a known `bundle_id` is a no-op.
/// - **TTL/eviction**: [`BundleStore::evict_expired`] removes bundles past
///   their lifetime.
/// - **Pending listing**: [`BundleStore::list_pending`] returns non-expired
///   bundles, optionally filtered by source node.
pub struct BundleStore {
    db: Db,
}

impl BundleStore {
    /// Open (or create) a store at `path`.
    pub fn new(path: &str) -> Result<Self> {
        let db =
            sled::open(path).map_err(|e| abos_common::error::Error::StorageError(e.to_string()))?;
        Ok(Self { db })
    }

    /// Store a bundle. Returns `Ok(true)` if newly inserted, `Ok(false)` if a
    /// bundle with this id already existed (dedup).
    pub fn store_bundle(&self, bundle: &Bundle) -> Result<bool> {
        if self.db.contains_key(&bundle.bundle_id[..]).unwrap_or(false) {
            return Ok(false);
        }
        let value = bincode::serialize(bundle)
            .map_err(|e| abos_common::error::Error::StorageError(e.to_string()))?;
        self.db
            .insert(&bundle.bundle_id[..], value)
            .map_err(|e| abos_common::error::Error::StorageError(e.to_string()))?;
        Ok(true)
    }

    /// Retrieve a bundle by id.
    pub fn retrieve_bundle(&self, bundle_id: &[u8; 32]) -> Result<Option<Bundle>> {
        match self
            .db
            .get(&bundle_id[..])
            .map_err(|e| abos_common::error::Error::StorageError(e.to_string()))?
        {
            Some(ivec) => {
                let bundle: Bundle = bincode::deserialize(&ivec)
                    .map_err(|e| abos_common::error::Error::StorageError(e.to_string()))?;
                Ok(Some(bundle))
            }
            None => Ok(None),
        }
    }

    /// Whether a bundle with this id is stored.
    pub fn contains(&self, bundle_id: &[u8; 32]) -> bool {
        self.db.contains_key(&bundle_id[..]).unwrap_or(false)
    }

    /// Total number of stored bundles.
    pub fn len(&self) -> usize {
        self.db.len()
    }

    /// True when the store holds no bundles.
    pub fn is_empty(&self) -> bool {
        self.db.is_empty()
    }

    /// All stored bundles that have not yet expired at `now` (unix seconds).
    /// When `source` is given, only that node's bundles are returned.
    pub fn list_pending(&self, now: u64, source: Option<[u8; 32]>) -> Result<Vec<Bundle>> {
        let mut out = Vec::new();
        for entry in self.db.iter() {
            let (_, value) =
                entry.map_err(|e| abos_common::error::Error::StorageError(e.to_string()))?;
            let bundle: Bundle = bincode::deserialize(&value)
                .map_err(|e| abos_common::error::Error::StorageError(e.to_string()))?;
            if is_expired_at(&bundle, now) {
                continue;
            }
            if let Some(src) = source {
                if bundle.source_node != src {
                    continue;
                }
            }
            out.push(bundle);
        }
        Ok(out)
    }

    /// Remove all bundles whose lifetime has elapsed at `now` (unix seconds).
    /// Returns the number of bundles evicted.
    pub fn evict_expired(&self, now: u64) -> Result<usize> {
        let mut doomed = Vec::new();
        for entry in self.db.iter() {
            let (key, value) =
                entry.map_err(|e| abos_common::error::Error::StorageError(e.to_string()))?;
            let bundle: Bundle = bincode::deserialize(&value)
                .map_err(|e| abos_common::error::Error::StorageError(e.to_string()))?;
            if is_expired_at(&bundle, now) {
                doomed.push(key);
            }
        }
        for key in &doomed {
            self.db
                .remove(key)
                .map_err(|e| abos_common::error::Error::StorageError(e.to_string()))?;
        }
        Ok(doomed.len())
    }

    /// Flush pending writes to disk (durability hook for shutdown).
    pub fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| abos_common::error::Error::StorageError(e.to_string()))?;
        Ok(())
    }
}

/// Expiry predicate with an injected clock (mirrors
/// `abos_protocol::bundle::is_bundle_expired`, kept local so `abos-storage`
/// does not depend on `abos-protocol`).
fn is_expired_at(bundle: &Bundle, now: u64) -> bool {
    now > bundle
        .creation_timestamp
        .saturating_add(bundle.lifetime_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(id: u8, source: u8, created: u64, lifetime: u64) -> Bundle {
        Bundle {
            bundle_id: [id; 32],
            source_node: [source; 32],
            creation_timestamp: created,
            lifetime_seconds: lifetime,
            payload: vec![id],
            hop_count: 0,
            ttl: lifetime as u32,
        }
    }

    fn temp_store(tag: &str) -> BundleStore {
        let path = std::env::temp_dir().join(format!("abos_test_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        BundleStore::new(path.to_str().unwrap()).expect("open store")
    }

    #[test]
    fn store_and_retrieve_roundtrip() {
        let store = temp_store("roundtrip");
        let b = bundle(1, 9, 100, 3600);
        assert!(store.store_bundle(&b).unwrap(), "first insert is new");
        let got = store.retrieve_bundle(&[1; 32]).unwrap().expect("found");
        assert_eq!(got.source_node, [9; 32]);
        assert_eq!(got.payload, vec![1]);
    }

    #[test]
    fn dedup_on_insert() {
        let store = temp_store("dedup");
        let b = bundle(2, 9, 100, 3600);
        assert!(store.store_bundle(&b).unwrap());
        assert!(!store.store_bundle(&b).unwrap(), "duplicate is dropped");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn eviction_removes_expired_keeps_fresh() {
        let store = temp_store("evict");
        assert!(store.store_bundle(&bundle(1, 9, 100, 10)).unwrap()); // expires at 110
        assert!(store.store_bundle(&bundle(2, 9, 9999, 10)).unwrap()); // never expires pre-500
        let evicted = store.evict_expired(500).unwrap();
        assert_eq!(evicted, 1);
        assert!(store.retrieve_bundle(&[1; 32]).unwrap().is_none());
        assert!(store.retrieve_bundle(&[2; 32]).unwrap().is_some());
    }

    #[test]
    fn pending_listing_filters_expired_and_source() {
        let store = temp_store("pending");
        store.store_bundle(&bundle(1, 9, 100, 10)).unwrap(); // expired at now=500
        store.store_bundle(&bundle(2, 9, 100, 99999)).unwrap(); // live, source 9
        store.store_bundle(&bundle(3, 7, 100, 99999)).unwrap(); // live, source 7

        let all_live = store.list_pending(500, None).unwrap();
        assert_eq!(all_live.len(), 2);

        let src9 = store.list_pending(500, Some([9; 32])).unwrap();
        assert_eq!(src9.len(), 1);
        assert_eq!(src9[0].bundle_id, [2; 32]);
    }
}
