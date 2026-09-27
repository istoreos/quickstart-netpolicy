use super::{PolicyError, PolicyErrorCode, PolicySnapshot, MAX_DEVICE_POLICIES};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const POLICY_SCHEMA_VERSION: u32 = 1;
const MAX_POLICY_FILE_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadSource {
    Empty,
    Primary,
    Backup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPolicySnapshot {
    pub snapshot: PolicySnapshot,
    pub source: LoadSource,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyFilePayload {
    schema_version: u32,
    revision: u64,
    policies: Vec<super::StoredDevicePolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyFileEnvelope {
    payload: PolicyFilePayload,
    checksum: String,
}

#[derive(Debug, Clone)]
pub struct PolicyStore {
    primary: PathBuf,
    backup: PathBuf,
    temporary: PathBuf,
}

impl PolicyStore {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let primary = data_dir.as_ref().join("policies-v1.json");
        Self {
            backup: primary.with_extension("json.bak"),
            temporary: primary.with_extension("json.tmp"),
            primary,
        }
    }

    pub fn load(&self) -> Result<LoadedPolicySnapshot, PolicyError> {
        if !self.primary.exists() && !self.backup.exists() {
            return Ok(LoadedPolicySnapshot {
                snapshot: empty_snapshot(),
                source: LoadSource::Empty,
            });
        }
        match read_snapshot(&self.primary) {
            Ok(snapshot) => Ok(LoadedPolicySnapshot {
                snapshot,
                source: LoadSource::Primary,
            }),
            Err(primary_error) => match read_snapshot(&self.backup) {
                Ok(snapshot) => Ok(LoadedPolicySnapshot {
                    snapshot,
                    source: LoadSource::Backup,
                }),
                Err(_) => Err(primary_error),
            },
        }
    }

    pub fn save(&self, snapshot: &PolicySnapshot) -> Result<(), PolicyError> {
        validate_snapshot(snapshot)?;
        let parent = self
            .primary
            .parent()
            .ok_or_else(|| storage_error("policy path has no parent"))?;
        fs::create_dir_all(parent).map_err(|error| storage_error(format!("create policy directory: {}", error)))?;

        let payload = PolicyFilePayload {
            schema_version: snapshot.schema_version,
            revision: snapshot.revision,
            policies: snapshot.policies.clone(),
        };
        let payload_bytes = serde_json::to_vec(&payload).map_err(|error| storage_error(format!("encode policy payload: {}", error)))?;
        let envelope = PolicyFileEnvelope {
            checksum: checksum(&payload_bytes),
            payload,
        };
        let encoded = serde_json::to_vec_pretty(&envelope).map_err(|error| storage_error(format!("encode policy file: {}", error)))?;
        if encoded.len() as u64 > MAX_POLICY_FILE_BYTES {
            return Err(capacity_error("policy file exceeds 1 MiB"));
        }

        if self.primary.exists() {
            let current = read_snapshot(&self.primary)?;
            write_snapshot_file(&self.temporary, &current)?;
            fs::rename(&self.temporary, &self.backup).map_err(|error| storage_error(format!("replace policy backup: {}", error)))?;
        }

        write_bytes(&self.temporary, &encoded)?;
        fs::rename(&self.temporary, &self.primary).map_err(|error| storage_error(format!("replace policy file: {}", error)))?;
        sync_directory(parent)?;
        Ok(())
    }
}

fn write_snapshot_file(path: &Path, snapshot: &PolicySnapshot) -> Result<(), PolicyError> {
    let payload = PolicyFilePayload {
        schema_version: snapshot.schema_version,
        revision: snapshot.revision,
        policies: snapshot.policies.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload).map_err(|error| storage_error(format!("encode backup payload: {}", error)))?;
    let encoded = serde_json::to_vec_pretty(&PolicyFileEnvelope {
        checksum: checksum(&payload_bytes),
        payload,
    })
    .map_err(|error| storage_error(format!("encode backup: {}", error)))?;
    write_bytes(path, &encoded)
}

fn write_bytes(path: &Path, encoded: &[u8]) -> Result<(), PolicyError> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|error| storage_error(format!("open temporary policy file: {}", error)))?;
    file.write_all(encoded)
        .map_err(|error| storage_error(format!("write temporary policy file: {}", error)))?;
    file.sync_all()
        .map_err(|error| storage_error(format!("sync temporary policy file: {}", error)))
}

fn read_snapshot(path: &Path) -> Result<PolicySnapshot, PolicyError> {
    let metadata = fs::metadata(path).map_err(|error| storage_error(format!("stat {}: {}", path.display(), error)))?;
    if metadata.len() > MAX_POLICY_FILE_BYTES {
        return Err(capacity_error("policy file exceeds 1 MiB"));
    }
    let bytes = fs::read(path).map_err(|error| storage_error(format!("read {}: {}", path.display(), error)))?;
    let envelope: PolicyFileEnvelope =
        serde_json::from_slice(&bytes).map_err(|error| storage_error(format!("decode {}: {}", path.display(), error)))?;
    let payload_bytes =
        serde_json::to_vec(&envelope.payload).map_err(|error| storage_error(format!("encode checksum payload: {}", error)))?;
    if checksum(&payload_bytes) != envelope.checksum {
        return Err(storage_error(format!("checksum mismatch in {}", path.display())));
    }
    let snapshot = PolicySnapshot {
        schema_version: envelope.payload.schema_version,
        revision: envelope.payload.revision,
        policies: envelope.payload.policies,
    };
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn validate_snapshot(snapshot: &PolicySnapshot) -> Result<(), PolicyError> {
    if snapshot.schema_version != POLICY_SCHEMA_VERSION {
        return Err(storage_error(format!(
            "unsupported policy schema version {}",
            snapshot.schema_version
        )));
    }
    if snapshot.policies.len() > MAX_DEVICE_POLICIES {
        return Err(capacity_error("policy count exceeds the supported maximum"));
    }
    Ok(())
}

fn empty_snapshot() -> PolicySnapshot {
    PolicySnapshot {
        schema_version: POLICY_SCHEMA_VERSION,
        revision: 0,
        policies: Vec::new(),
    }
}

fn checksum(payload: &[u8]) -> String {
    format!("{:08x}", crc32fast::hash(payload))
}

fn sync_directory(path: &Path) -> Result<(), PolicyError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| storage_error(format!("sync policy directory: {}", error)))
}

fn storage_error(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: PolicyErrorCode::Unavailable,
        message: message.into(),
        field: None,
    }
}

fn capacity_error(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: PolicyErrorCode::CapacityExceeded,
        message: message.into(),
        field: Some("policies".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DeviceIdentity, EffectiveState, PolicyOwner, PolicySource, StoredDevicePolicy};

    fn temporary_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!("quickstart-netpolicy-store-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn snapshot(revision: u64) -> PolicySnapshot {
        PolicySnapshot {
            schema_version: 1,
            revision,
            policies: vec![StoredDevicePolicy {
                id: "policy-1".to_string(),
                revision,
                source: PolicySource::Quickstart,
                owner: PolicyOwner {
                    product: "quickstart".to_string(),
                    instance: "router-a".to_string(),
                },
                device: DeviceIdentity::Mac {
                    value: "AA:BB:CC:DD:EE:FF".to_string(),
                },
                rate_limit: None,
                quota: None,
                state: EffectiveState::Configured,
            }],
        }
    }

    #[test]
    fn persists_and_reloads_complete_snapshot() {
        let directory = temporary_directory();
        let store = PolicyStore::new(&directory);
        store.save(&snapshot(1)).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.source, LoadSource::Primary);
        assert_eq!(loaded.snapshot, snapshot(1));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovers_last_valid_backup_after_primary_corruption() {
        let directory = temporary_directory();
        let store = PolicyStore::new(&directory);
        store.save(&snapshot(1)).unwrap();
        store.save(&snapshot(2)).unwrap();
        fs::write(&store.primary, b"{truncated").unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.source, LoadSource::Backup);
        assert_eq!(loaded.snapshot.revision, 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_checksum_and_capacity_violations() {
        let directory = temporary_directory();
        let store = PolicyStore::new(&directory);
        store.save(&snapshot(1)).unwrap();
        let mut contents = fs::read_to_string(&store.primary).unwrap();
        contents = contents.replace("policy-1", "policy-X");
        fs::write(&store.primary, contents).unwrap();
        assert_eq!(store.load().unwrap_err().code, PolicyErrorCode::Unavailable);

        let mut too_many = snapshot(2);
        too_many.policies = vec![too_many.policies[0].clone(); MAX_DEVICE_POLICIES + 1];
        assert_eq!(store.save(&too_many).unwrap_err().code, PolicyErrorCode::CapacityExceeded);
        fs::remove_dir_all(directory).unwrap();
    }
}
