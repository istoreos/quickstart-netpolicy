use super::store::{LoadSource, PolicyStore};
use super::{
    validate_mutation_request, EffectiveState, EngineHealth, EngineHealthState, PolicyChange, PolicyChangeKind, PolicyError,
    PolicyErrorCode, PolicyMutationRequest, PolicyPlan, PolicySnapshot, PolicySource, StoredDevicePolicy, TrafficPolicyEngine,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub trait PolicyDataPlane {
    fn apply(&mut self, desired: &PolicySnapshot) -> Result<(), String>;
    fn verify(&self, desired: &PolicySnapshot) -> Result<(), String>;
    fn restore(&mut self, previous: &PolicySnapshot) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransactionState {
    Applying,
    Verifying,
    Committed,
    RollingBack,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionRecord {
    id: String,
    idempotency_key: String,
    state: TransactionState,
    before: PolicySnapshot,
    desired: PolicySnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TransactionJournal {
    path: PathBuf,
    temporary: PathBuf,
}

impl TransactionJournal {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let path = data_dir.as_ref().join("transaction-v1.json");
        Self {
            temporary: path.with_extension("json.tmp"),
            path,
        }
    }

    fn load(&self) -> Result<Option<TransactionRecord>, PolicyError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&self.path).map_err(|error| unavailable(format!("read transaction journal: {}", error)))?;
        if bytes.len() > 2 << 20 {
            return Err(unavailable("transaction journal exceeds 2 MiB"));
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| unavailable(format!("decode transaction journal: {}", error)))
    }

    fn save(&self, record: &TransactionRecord) -> Result<(), PolicyError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| unavailable("transaction journal path has no parent"))?;
        fs::create_dir_all(parent).map_err(|error| unavailable(format!("create journal directory: {}", error)))?;
        let bytes = serde_json::to_vec_pretty(record).map_err(|error| unavailable(format!("encode transaction journal: {}", error)))?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&self.temporary)
            .map_err(|error| unavailable(format!("open temporary journal: {}", error)))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| unavailable(format!("write transaction journal: {}", error)))?;
        fs::rename(&self.temporary, &self.path).map_err(|error| unavailable(format!("replace transaction journal: {}", error)))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| unavailable(format!("sync journal directory: {}", error)))
    }
}

pub struct NativePolicyEngine<D: PolicyDataPlane> {
    store: PolicyStore,
    journal: TransactionJournal,
    data_plane: D,
    current: PolicySnapshot,
    last_transaction: Option<TransactionRecord>,
    interface: String,
}

impl<D: PolicyDataPlane> NativePolicyEngine<D> {
    pub fn open(
        store: PolicyStore,
        journal: TransactionJournal,
        mut data_plane: D,
        interface: impl Into<String>,
    ) -> Result<Self, PolicyError> {
        let loaded = store.load()?;
        let mut current = loaded.snapshot;
        if loaded.source == LoadSource::Backup {
            store.restore(&current)?;
        }
        let mut last_transaction = journal.load()?;
        if let Some(record) = last_transaction.as_mut() {
            if matches!(
                record.state,
                TransactionState::Applying | TransactionState::Verifying | TransactionState::RollingBack
            ) {
                data_plane
                    .restore(&record.before)
                    .map_err(|error| rollback_error(format!("recover data plane: {}", error)))?;
                store.restore(&record.before)?;
                record.state = TransactionState::RolledBack;
                record.error = Some("recovered incomplete transaction at startup".to_string());
                journal.save(record)?;
                current = record.before.clone();
            }
        }
        data_plane
            .apply(&current)
            .map_err(|error| unavailable(format!("reconcile persisted policy: {}", error)))?;
        data_plane
            .verify(&current)
            .map_err(|error| unavailable(format!("verify persisted policy: {}", error)))?;
        Ok(Self {
            store,
            journal,
            data_plane,
            current,
            last_transaction,
            interface: interface.into(),
        })
    }

    fn build_desired(&self, request: &PolicyMutationRequest) -> Result<PolicySnapshot, PolicyError> {
        let normalized = validate_mutation_request(request)?;
        let mut retained: Vec<StoredDevicePolicy> = self
            .current
            .policies
            .iter()
            .filter(|policy| policy.owner != request.owner)
            .cloned()
            .collect();
        let existing: BTreeMap<String, &StoredDevicePolicy> = self
            .current
            .policies
            .iter()
            .filter(|policy| policy.owner == request.owner)
            .filter_map(|policy| policy.device.stable_key().ok().map(|key| (key, policy)))
            .collect();
        let next_revision = self.current.revision + 1;
        for policy in normalized {
            let key = policy.device.stable_key()?;
            let id = existing
                .get(&key)
                .map(|policy| policy.id.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            retained.push(StoredDevicePolicy {
                id,
                revision: next_revision,
                source: PolicySource::Quickstart,
                owner: request.owner.clone(),
                device: policy.device,
                rate_limit: policy.rate_limit,
                quota: policy.quota,
                state: EffectiveState::Configured,
            });
        }
        retained.sort_by_key(|policy| policy.device.stable_key().unwrap_or_default());
        Ok(PolicySnapshot {
            schema_version: 1,
            revision: next_revision,
            policies: retained,
        })
    }

    fn rollback_record(&mut self, record: &mut TransactionRecord, reason: String) -> Result<(), PolicyError> {
        record.state = TransactionState::RollingBack;
        record.error = Some(reason);
        self.journal.save(record)?;
        self.data_plane
            .restore(&record.before)
            .map_err(|error| rollback_error(format!("restore data plane: {}", error)))?;
        self.store.restore(&record.before)?;
        self.current = record.before.clone();
        record.state = TransactionState::RolledBack;
        self.journal.save(record)?;
        self.last_transaction = Some(record.clone());
        Ok(())
    }
}

impl<D: PolicyDataPlane> TrafficPolicyEngine for NativePolicyEngine<D> {
    fn inspect(&self) -> Result<PolicySnapshot, PolicyError> {
        Ok(self.current.clone())
    }

    fn plan(&self, request: &PolicyMutationRequest) -> Result<PolicyPlan, PolicyError> {
        if request.expected_revision != self.current.revision {
            return Err(PolicyError {
                code: PolicyErrorCode::RevisionConflict,
                message: format!(
                    "expected revision {}, current revision is {}",
                    request.expected_revision, self.current.revision
                ),
                field: Some("expectedRevision".to_string()),
            });
        }
        let desired = self.build_desired(request)?;
        let old_keys: BTreeSet<String> = self
            .current
            .policies
            .iter()
            .filter(|policy| policy.owner == request.owner)
            .filter_map(|policy| policy.device.stable_key().ok())
            .collect();
        let new_keys: BTreeSet<String> = desired
            .policies
            .iter()
            .filter(|policy| policy.owner == request.owner)
            .filter_map(|policy| policy.device.stable_key().ok())
            .collect();
        let mut changes = Vec::new();
        for key in old_keys.union(&new_keys) {
            let kind = if !old_keys.contains(key) {
                PolicyChangeKind::Create
            } else if !new_keys.contains(key) {
                PolicyChangeKind::Delete
            } else {
                PolicyChangeKind::Update
            };
            let value = key.strip_prefix("mac:").unwrap_or(key).to_string();
            changes.push(PolicyChange {
                kind,
                device: super::DeviceIdentity::Mac { value },
            });
        }
        Ok(PolicyPlan {
            id: uuid::Uuid::new_v4().to_string(),
            base_revision: self.current.revision,
            next_revision: desired.revision,
            changes,
            warnings: Vec::new(),
        })
    }

    fn apply(&mut self, plan: &PolicyPlan, request: &PolicyMutationRequest) -> Result<PolicySnapshot, PolicyError> {
        if let Some(record) = &self.last_transaction {
            if record.idempotency_key == request.idempotency_key && record.state == TransactionState::Committed {
                return Ok(self.current.clone());
            }
        }
        if plan.base_revision != self.current.revision || request.expected_revision != self.current.revision {
            return Err(PolicyError {
                code: PolicyErrorCode::RevisionConflict,
                message: "policy revision changed after plan creation".to_string(),
                field: Some("expectedRevision".to_string()),
            });
        }
        let desired = self.build_desired(request)?;
        if desired.revision != plan.next_revision {
            return Err(PolicyError {
                code: PolicyErrorCode::Conflict,
                message: "plan does not match requested mutation".to_string(),
                field: None,
            });
        }
        let mut record = TransactionRecord {
            id: plan.id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            state: TransactionState::Applying,
            before: self.current.clone(),
            desired: desired.clone(),
            error: None,
        };
        self.journal.save(&record)?;
        if let Err(error) = self.data_plane.apply(&desired) {
            self.rollback_record(&mut record, format!("apply failed: {}", error))?;
            return Err(unavailable("data-plane apply failed"));
        }
        record.state = TransactionState::Verifying;
        self.journal.save(&record)?;
        if let Err(error) = self.data_plane.verify(&desired) {
            self.rollback_record(&mut record, format!("verification failed: {}", error))?;
            return Err(PolicyError {
                code: PolicyErrorCode::VerificationFailed,
                message: "data-plane verification failed".to_string(),
                field: None,
            });
        }
        let mut committed = desired;
        for policy in &mut committed.policies {
            policy.state = EffectiveState::Effective;
        }
        if let Err(error) = self.store.save(&committed) {
            self.rollback_record(&mut record, format!("persist failed: {}", error.message))?;
            return Err(error);
        }
        record.desired = committed.clone();
        record.state = TransactionState::Committed;
        self.journal.save(&record)?;
        self.current = committed.clone();
        self.last_transaction = Some(record);
        Ok(committed)
    }

    fn verify(&self, snapshot: &PolicySnapshot) -> Result<(), PolicyError> {
        self.data_plane.verify(snapshot).map_err(|error| PolicyError {
            code: PolicyErrorCode::VerificationFailed,
            message: error,
            field: None,
        })
    }

    fn rollback(&mut self, revision: u64) -> Result<PolicySnapshot, PolicyError> {
        let Some(mut record) = self.last_transaction.clone() else {
            return Err(rollback_error("no transaction is available for rollback"));
        };
        if record.before.revision != revision {
            return Err(rollback_error("requested rollback revision is not available"));
        }
        self.rollback_record(&mut record, "explicit rollback".to_string())?;
        Ok(self.current.clone())
    }

    fn health(&self) -> EngineHealth {
        EngineHealth {
            state: EngineHealthState::Healthy,
            interface: self.interface.clone(),
            revision: self.current.revision,
            reasons: Vec::new(),
        }
    }
}

fn unavailable(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: PolicyErrorCode::Unavailable,
        message: message.into(),
        field: None,
    }
}

fn rollback_error(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: PolicyErrorCode::RollbackFailed,
        message: message.into(),
        field: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DeviceIdentity, DevicePolicyInput, PolicyOwner, RateLimitPolicy};
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Default)]
    struct FakeDataPlane {
        apply_calls: Rc<Cell<u32>>,
        restore_calls: Rc<Cell<u32>>,
        fail_apply: bool,
        fail_verify: bool,
    }

    impl PolicyDataPlane for FakeDataPlane {
        fn apply(&mut self, _desired: &PolicySnapshot) -> Result<(), String> {
            self.apply_calls.set(self.apply_calls.get() + 1);
            if self.fail_apply {
                Err("injected apply failure".to_string())
            } else {
                Ok(())
            }
        }

        fn verify(&self, _desired: &PolicySnapshot) -> Result<(), String> {
            if self.fail_verify {
                Err("injected verification failure".to_string())
            } else {
                Ok(())
            }
        }

        fn restore(&mut self, _previous: &PolicySnapshot) -> Result<(), String> {
            self.restore_calls.set(self.restore_calls.get() + 1);
            Ok(())
        }
    }

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!("quickstart-netpolicy-engine-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn request(revision: u64, key: &str) -> PolicyMutationRequest {
        PolicyMutationRequest {
            expected_revision: revision,
            idempotency_key: key.to_string(),
            owner: PolicyOwner {
                product: "quickstart".to_string(),
                instance: "router-a".to_string(),
            },
            policies: vec![DevicePolicyInput {
                device: DeviceIdentity::Mac {
                    value: "AA:BB:CC:DD:EE:FF".to_string(),
                },
                rate_limit: Some(RateLimitPolicy {
                    enabled: true,
                    upload_bits_per_second: 10_000_000,
                    download_bits_per_second: 20_000_000,
                }),
                quota: None,
            }],
        }
    }

    fn engine(path: &Path, data_plane: FakeDataPlane) -> NativePolicyEngine<FakeDataPlane> {
        NativePolicyEngine::open(PolicyStore::new(path), TransactionJournal::new(path), data_plane, "br-lan").unwrap()
    }

    #[test]
    fn plan_is_read_only_and_rejects_stale_revision() {
        let path = directory();
        let engine = engine(&path, FakeDataPlane::default());
        let plan = engine.plan(&request(0, "one")).unwrap();
        assert_eq!(plan.base_revision, 0);
        assert!(!path.join("policies-v1.json").exists());
        assert_eq!(
            engine.plan(&request(1, "stale")).unwrap_err().code,
            PolicyErrorCode::RevisionConflict
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn applies_once_and_reuses_committed_idempotency_key() {
        let path = directory();
        let calls = Rc::new(Cell::new(0));
        let mut engine = engine(
            &path,
            FakeDataPlane {
                apply_calls: calls.clone(),
                ..Default::default()
            },
        );
        let request = request(0, "same-key");
        let plan = engine.plan(&request).unwrap();
        assert_eq!(engine.apply(&plan, &request).unwrap().revision, 1);
        assert_eq!(engine.apply(&plan, &request).unwrap().revision, 1);
        assert_eq!(calls.get(), 2);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn rolls_back_apply_and_verification_failures() {
        for fail_verify in [false, true] {
            let path = directory();
            let restores = Rc::new(Cell::new(0));
            let mut engine = engine(
                &path,
                FakeDataPlane {
                    restore_calls: restores.clone(),
                    ..Default::default()
                },
            );
            engine.data_plane.fail_apply = !fail_verify;
            engine.data_plane.fail_verify = fail_verify;
            let request = request(0, if fail_verify { "verify" } else { "apply" });
            let plan = engine.plan(&request).unwrap();
            assert!(engine.apply(&plan, &request).is_err());
            assert_eq!(engine.inspect().unwrap().revision, 0);
            assert_eq!(restores.get(), 1);
            fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn recovers_unfinished_transaction_on_open() {
        let path = directory();
        let store = PolicyStore::new(&path);
        let journal = TransactionJournal::new(&path);
        let before = store.load().unwrap().snapshot;
        let desired = PolicySnapshot {
            schema_version: 1,
            revision: 1,
            policies: Vec::new(),
        };
        journal
            .save(&TransactionRecord {
                id: "tx".to_string(),
                idempotency_key: "key".to_string(),
                state: TransactionState::Applying,
                before,
                desired,
                error: None,
            })
            .unwrap();
        let restores = Rc::new(Cell::new(0));
        let engine = NativePolicyEngine::open(
            store,
            journal,
            FakeDataPlane {
                restore_calls: restores.clone(),
                ..Default::default()
            },
            "br-lan",
        )
        .unwrap();
        assert_eq!(engine.inspect().unwrap().revision, 0);
        assert_eq!(restores.get(), 1);
        fs::remove_dir_all(path).unwrap();
    }
}
