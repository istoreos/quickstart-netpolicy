use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const POLICY_INTERFACE_VERSION: &str = "1";
pub const MAX_DEVICE_POLICIES: usize = 1024;
pub const MAX_RATE_BITS_PER_SECOND: u64 = 100_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyErrorCode {
    ValidationFailed,
    CapacityExceeded,
    RevisionConflict,
    Conflict,
    Unavailable,
    VerificationFailed,
    RollbackFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyError {
    pub code: PolicyErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl PolicyError {
    fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: PolicyErrorCode::ValidationFailed,
            message: message.into(),
            field: Some(field.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeviceIdentity {
    Mac { value: String },
}

impl DeviceIdentity {
    pub fn normalized(&self) -> Result<Self, PolicyError> {
        match self {
            Self::Mac { value } => normalize_mac(value)
                .map(|value| Self::Mac { value })
                .ok_or_else(|| PolicyError::validation("device.value", "invalid MAC address")),
        }
    }

    pub fn stable_key(&self) -> Result<String, PolicyError> {
        match self.normalized()? {
            Self::Mac { value } => Ok(format!("mac:{}", value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitPolicy {
    pub enabled: bool,
    pub upload_bits_per_second: u64,
    pub download_bits_per_second: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaPeriod {
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Lifetime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaAction {
    Notify,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficQuotaPolicy {
    pub enabled: bool,
    pub period: QuotaPeriod,
    pub limit_bytes: u64,
    pub action: QuotaAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySource {
    Quickstart,
    ImportedBandix,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyOwner {
    pub product: String,
    pub instance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePolicyInput {
    pub device: DeviceIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<TrafficQuotaPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyMutationRequest {
    pub expected_revision: u64,
    pub idempotency_key: String,
    pub owner: PolicyOwner,
    pub policies: Vec<DevicePolicyInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveState {
    Configured,
    Loaded,
    Effective,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredDevicePolicy {
    pub id: String,
    pub revision: u64,
    pub source: PolicySource,
    pub owner: PolicyOwner,
    pub device: DeviceIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<TrafficQuotaPolicy>,
    pub state: EffectiveState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySnapshot {
    pub schema_version: u32,
    pub revision: u64,
    pub policies: Vec<StoredDevicePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyChangeKind {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyChange {
    pub kind: PolicyChangeKind,
    pub device: DeviceIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyPlan {
    pub id: String,
    pub base_revision: u64,
    pub next_revision: u64,
    pub changes: Vec<PolicyChange>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineHealthState {
    Healthy,
    Degraded,
    Unavailable,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineHealth {
    pub state: EngineHealthState,
    pub interface: String,
    pub revision: u64,
    pub reasons: Vec<String>,
}

pub trait TrafficPolicyEngine {
    fn inspect(&self) -> Result<PolicySnapshot, PolicyError>;
    fn plan(&self, request: &PolicyMutationRequest) -> Result<PolicyPlan, PolicyError>;
    fn apply(&mut self, plan: &PolicyPlan, request: &PolicyMutationRequest) -> Result<PolicySnapshot, PolicyError>;
    fn verify(&self, snapshot: &PolicySnapshot) -> Result<(), PolicyError>;
    fn rollback(&mut self, revision: u64) -> Result<PolicySnapshot, PolicyError>;
    fn health(&self) -> EngineHealth;
}

pub fn validate_mutation_request(request: &PolicyMutationRequest) -> Result<Vec<DevicePolicyInput>, PolicyError> {
    if request.idempotency_key.trim().is_empty() || request.idempotency_key.len() > 128 {
        return Err(PolicyError::validation(
            "idempotencyKey",
            "idempotency key must contain 1 to 128 characters",
        ));
    }
    if request.owner.product.trim().is_empty() || request.owner.instance.trim().is_empty() {
        return Err(PolicyError::validation("owner", "owner product and instance are required"));
    }
    if request.policies.len() > MAX_DEVICE_POLICIES {
        return Err(PolicyError {
            code: PolicyErrorCode::CapacityExceeded,
            message: format!("at most {} device policies are allowed", MAX_DEVICE_POLICIES),
            field: Some("policies".to_string()),
        });
    }

    let mut normalized = Vec::with_capacity(request.policies.len());
    let mut devices = HashSet::with_capacity(request.policies.len());
    for (index, policy) in request.policies.iter().enumerate() {
        let device = policy.device.normalized()?;
        let stable_key = device.stable_key()?;
        if !devices.insert(stable_key) {
            return Err(PolicyError::validation(
                format!("policies[{}].device", index),
                "duplicate device policy",
            ));
        }
        if let Some(rate) = &policy.rate_limit {
            validate_rate_limit(rate, index)?;
        }
        if let Some(quota) = &policy.quota {
            validate_quota(quota, index)?;
        }
        normalized.push(DevicePolicyInput {
            device,
            rate_limit: policy.rate_limit.clone(),
            quota: policy.quota.clone(),
        });
    }
    Ok(normalized)
}

fn validate_rate_limit(rate: &RateLimitPolicy, index: usize) -> Result<(), PolicyError> {
    if rate.upload_bits_per_second > MAX_RATE_BITS_PER_SECOND || rate.download_bits_per_second > MAX_RATE_BITS_PER_SECOND {
        return Err(PolicyError::validation(
            format!("policies[{}].rateLimit", index),
            "rate limit exceeds the supported maximum",
        ));
    }
    if rate.enabled && rate.upload_bits_per_second == 0 && rate.download_bits_per_second == 0 {
        return Err(PolicyError::validation(
            format!("policies[{}].rateLimit", index),
            "an enabled rate limit requires an upload or download limit",
        ));
    }
    Ok(())
}

fn validate_quota(quota: &TrafficQuotaPolicy, index: usize) -> Result<(), PolicyError> {
    if quota.enabled && quota.limit_bytes == 0 {
        return Err(PolicyError::validation(
            format!("policies[{}].quota.limitBytes", index),
            "an enabled quota requires a positive byte limit",
        ));
    }
    Ok(())
}

fn normalize_mac(value: &str) -> Option<String> {
    let hex: String = value
        .chars()
        .filter(|character| *character != ':' && *character != '-')
        .collect();
    if hex.len() != 12 || !hex.chars().all(|character| character.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        (0..6)
            .map(|index| hex[index * 2..index * 2 + 2].to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(policy: DevicePolicyInput) -> PolicyMutationRequest {
        PolicyMutationRequest {
            expected_revision: 0,
            idempotency_key: "test-1".to_string(),
            owner: PolicyOwner {
                product: "quickstart".to_string(),
                instance: "router-a".to_string(),
            },
            policies: vec![policy],
        }
    }

    fn valid_policy(mac: &str) -> DevicePolicyInput {
        DevicePolicyInput {
            device: DeviceIdentity::Mac { value: mac.to_string() },
            rate_limit: Some(RateLimitPolicy {
                enabled: true,
                upload_bits_per_second: 10_000_000,
                download_bits_per_second: 20_000_000,
            }),
            quota: None,
        }
    }

    #[test]
    fn normalizes_mac_without_leaking_provider_fields() {
        let policies = validate_mutation_request(&request(valid_policy("aa-bb-cc-dd-ee-ff"))).unwrap();
        assert_eq!(policies[0].device.stable_key().unwrap(), "mac:AA:BB:CC:DD:EE:FF");
        let json = serde_json::to_string(&policies[0]).unwrap();
        assert!(!json.contains("bandix"));
        assert!(!json.contains("ebpf"));
        assert!(!json.contains("tc_"));
    }

    #[test]
    fn rejects_invalid_and_duplicate_devices() {
        let error = validate_mutation_request(&request(valid_policy("not-a-mac"))).unwrap_err();
        assert_eq!(error.code, PolicyErrorCode::ValidationFailed);

        let mut duplicate = request(valid_policy("AA:BB:CC:DD:EE:FF"));
        duplicate.policies.push(valid_policy("aa-bb-cc-dd-ee-ff"));
        let error = validate_mutation_request(&duplicate).unwrap_err();
        assert_eq!(error.field.as_deref(), Some("policies[1].device"));
    }

    #[test]
    fn rejects_invalid_rate_and_quota_values() {
        let mut policy = valid_policy("AA:BB:CC:DD:EE:FF");
        policy.rate_limit.as_mut().unwrap().upload_bits_per_second = MAX_RATE_BITS_PER_SECOND + 1;
        assert_eq!(
            validate_mutation_request(&request(policy)).unwrap_err().code,
            PolicyErrorCode::ValidationFailed
        );

        let mut policy = valid_policy("AA:BB:CC:DD:EE:FF");
        policy.quota = Some(TrafficQuotaPolicy {
            enabled: true,
            period: QuotaPeriod::Month,
            limit_bytes: 0,
            action: QuotaAction::Block,
        });
        assert_eq!(
            validate_mutation_request(&request(policy)).unwrap_err().code,
            PolicyErrorCode::ValidationFailed
        );
    }

    #[test]
    fn round_trips_the_v1_contract() {
        let original = request(valid_policy("AA:BB:CC:DD:EE:FF"));
        let json = serde_json::to_string(&original).unwrap();
        let decoded: PolicyMutationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }
}
