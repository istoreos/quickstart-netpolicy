use super::transaction::PolicyDataPlane;
use super::{DeviceIdentity, PolicySnapshot, QuotaAction, QuotaPeriod};
use aya::maps::{HashMap as AyaHashMap, MapData};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const RATE_LIMIT_MAP: &str = "QSNP_RATE_LIMIT";
pub const RATE_BUCKET_MAP: &str = "QSNP_BUCKETS";
pub const QUOTA_LIMIT_MAP: &str = "QSNP_QUOTA_LIM";
pub const QUOTA_BLOCK_MAP: &str = "QSNP_QUOTA_BLK";

pub type MacAddress = [u8; 6];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KernelPolicyState {
    /// Kernel ABI: [WAN download bytes/s, WAN upload bytes/s].
    pub rate_limits: BTreeMap<MacAddress, [u64; 2]>,
    /// Kernel ABI: minute/hour/day/week/month/lifetime absolute WAN byte thresholds.
    pub quota_thresholds: BTreeMap<MacAddress, [u64; 6]>,
}

pub trait KernelPolicyBackend {
    fn read_policy_state(&self) -> Result<KernelPolicyState, String>;
    fn replace_policy_state(&mut self, desired: &KernelPolicyState) -> Result<(), String>;
    fn read_wan_bytes(&self, mac: &MacAddress) -> Result<u64, String>;
}

/// Production adapter for the maps owned by the quickstart-netpolicy eBPF object.
/// The process owns the object for its full lifetime; map operations are serialized
/// by the policy coordinator.
pub struct AyaKernelPolicyBackend {
    ebpf: Arc<aya::Ebpf>,
}

impl AyaKernelPolicyBackend {
    pub fn new(ebpf: Arc<aya::Ebpf>) -> Self {
        Self { ebpf }
    }

    fn ebpf_mut(&mut self) -> &mut aya::Ebpf {
        // Aya requires a mutable handle to open a mutable map. This service is the
        // sole map writer and the transaction coordinator serializes calls.
        unsafe { &mut *(Arc::as_ptr(&self.ebpf) as *mut aya::Ebpf) }
    }
}

impl KernelPolicyBackend for AyaKernelPolicyBackend {
    fn read_policy_state(&self) -> Result<KernelPolicyState, String> {
        let rates = AyaHashMap::<&MapData, MacAddress, [u64; 2]>::try_from(
            self.ebpf
                .map(RATE_LIMIT_MAP)
                .ok_or_else(|| format!("{} map not found", RATE_LIMIT_MAP))?,
        )
        .map_err(|error| error.to_string())?;
        let quotas = AyaHashMap::<&MapData, MacAddress, [u64; 6]>::try_from(
            self.ebpf
                .map(QUOTA_LIMIT_MAP)
                .ok_or_else(|| format!("{} map not found", QUOTA_LIMIT_MAP))?,
        )
        .map_err(|error| error.to_string())?;
        Ok(KernelPolicyState {
            rate_limits: rates
                .iter()
                .map(|entry| entry.map_err(|error| error.to_string()))
                .collect::<Result<_, _>>()?,
            quota_thresholds: quotas
                .iter()
                .map(|entry| entry.map_err(|error| error.to_string()))
                .collect::<Result<_, _>>()?,
        })
    }

    fn replace_policy_state(&mut self, desired: &KernelPolicyState) -> Result<(), String> {
        let ebpf = self.ebpf_mut();
        reconcile_map(
            AyaHashMap::<_, MacAddress, [u64; 2]>::try_from(
                ebpf.map_mut(RATE_LIMIT_MAP)
                    .ok_or_else(|| format!("{} map not found", RATE_LIMIT_MAP))?,
            )
            .map_err(|error| error.to_string())?,
            &desired.rate_limits,
        )?;
        reconcile_map(
            AyaHashMap::<_, MacAddress, [u64; 6]>::try_from(
                ebpf.map_mut(QUOTA_LIMIT_MAP)
                    .ok_or_else(|| format!("{} map not found", QUOTA_LIMIT_MAP))?,
            )
            .map_err(|error| error.to_string())?,
            &desired.quota_thresholds,
        )?;

        // Buckets derive from rate limits and must not retain tokens from a prior
        // policy. Quota block flags derive from thresholds and must be recomputed.
        clear_map(
            AyaHashMap::<_, MacAddress, [u64; 4]>::try_from(
                ebpf.map_mut(RATE_BUCKET_MAP)
                    .ok_or_else(|| format!("{} map not found", RATE_BUCKET_MAP))?,
            )
            .map_err(|error| error.to_string())?,
        )?;
        clear_map(
            AyaHashMap::<_, MacAddress, u8>::try_from(
                ebpf.map_mut(QUOTA_BLOCK_MAP)
                    .ok_or_else(|| format!("{} map not found", QUOTA_BLOCK_MAP))?,
            )
            .map_err(|error| error.to_string())?,
        )?;
        Ok(())
    }

    fn read_wan_bytes(&self, mac: &MacAddress) -> Result<u64, String> {
        let traffic = AyaHashMap::<&MapData, MacAddress, [u64; 4]>::try_from(
            self.ebpf
                .map("QSNP_TRAFFIC")
                .ok_or_else(|| "QSNP_TRAFFIC map not found".to_string())?,
        )
        .map_err(|error| error.to_string())?;
        match traffic.get(mac, 0) {
            Ok(value) => Ok(value[2].saturating_add(value[3])),
            Err(aya::maps::MapError::KeyNotFound) => Ok(0),
            Err(error) => Err(error.to_string()),
        }
    }
}

fn reconcile_map<T: aya::Pod + Copy + PartialEq>(
    mut map: AyaHashMap<&mut MapData, MacAddress, T>,
    desired: &BTreeMap<MacAddress, T>,
) -> Result<(), String> {
    let existing = map
        .iter()
        .map(|entry| entry.map(|(key, _)| key).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    for (key, value) in desired {
        map.insert(key, value, 0).map_err(|error| error.to_string())?;
    }
    for key in existing {
        if !desired.contains_key(&key) {
            map.remove(&key).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn clear_map<T: aya::Pod>(mut map: AyaHashMap<&mut MapData, MacAddress, T>) -> Result<(), String> {
    let keys = map
        .iter()
        .map(|entry| entry.map(|(key, _)| key).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    for key in keys {
        map.remove(&key).map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub struct NativeDataPlane<B: KernelPolicyBackend> {
    backend: B,
    protected_macs: BTreeSet<MacAddress>,
    expected: Option<KernelPolicyState>,
}

impl<B: KernelPolicyBackend> NativeDataPlane<B> {
    pub fn new(backend: B, protected_macs: impl IntoIterator<Item = MacAddress>) -> Self {
        Self {
            backend,
            protected_macs: protected_macs.into_iter().collect(),
            expected: None,
        }
    }

    pub fn into_backend(self) -> B {
        self.backend
    }

    fn translate(&self, snapshot: &PolicySnapshot) -> Result<KernelPolicyState, String> {
        let mut state = KernelPolicyState::default();
        for policy in &snapshot.policies {
            let mac = identity_mac(&policy.device)?;
            if self.protected_macs.contains(&mac) {
                return Err(format!(
                    "refusing to apply traffic policy to protected router MAC {}",
                    format_mac(mac)
                ));
            }

            if let Some(rate) = policy.rate_limit.as_ref().filter(|rate| rate.enabled) {
                // Floor conversion guarantees the effective byte rate never exceeds
                // the requested bit rate. Values below 8 bit/s are rejected by the
                // domain validator because zero means unlimited in the kernel ABI.
                state
                    .rate_limits
                    .insert(mac, [rate.download_bits_per_second / 8, rate.upload_bits_per_second / 8]);
            }

            if let Some(quota) = policy.quota.as_ref().filter(|quota| quota.enabled) {
                // Notify-only quotas remain user-space observations. Only a block
                // action installs a kernel threshold.
                if quota.action == QuotaAction::Block {
                    let current = self.backend.read_wan_bytes(&mac)?;
                    let mut thresholds = [u64::MAX; 6];
                    thresholds[quota_index(&quota.period)] = current.saturating_add(quota.limit_bytes);
                    state.quota_thresholds.insert(mac, thresholds);
                }
            }
        }
        Ok(state)
    }
}

impl<B: KernelPolicyBackend> PolicyDataPlane for NativeDataPlane<B> {
    fn apply(&mut self, desired: &PolicySnapshot) -> Result<(), String> {
        let state = self.translate(desired)?;
        self.backend.replace_policy_state(&state)?;
        self.expected = Some(state);
        Ok(())
    }

    fn verify(&self, desired: &PolicySnapshot) -> Result<(), String> {
        let expected = self.expected.clone().map(Ok).unwrap_or_else(|| self.translate(desired))?;
        let actual = self.backend.read_policy_state()?;
        if actual == expected {
            Ok(())
        } else {
            Err(format!(
                "kernel policy state mismatch: expected {:?}, actual {:?}",
                expected, actual
            ))
        }
    }

    fn restore(&mut self, previous: &PolicySnapshot) -> Result<(), String> {
        let state = self.translate(previous)?;
        self.backend.replace_policy_state(&state)?;
        self.expected = Some(state);
        Ok(())
    }
}

fn identity_mac(identity: &DeviceIdentity) -> Result<MacAddress, String> {
    let DeviceIdentity::Mac { value } = identity;
    let octets = value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16).map_err(|_| format!("invalid normalized MAC {}", value)))
        .collect::<Result<Vec<_>, _>>()?;
    octets.try_into().map_err(|_| format!("invalid normalized MAC {}", value))
}

fn quota_index(period: &QuotaPeriod) -> usize {
    match period {
        QuotaPeriod::Minute => 0,
        QuotaPeriod::Hour => 1,
        QuotaPeriod::Day => 2,
        QuotaPeriod::Week => 3,
        QuotaPeriod::Month => 4,
        QuotaPeriod::Lifetime => 5,
    }
}

fn format_mac(mac: MacAddress) -> String {
    mac.iter().map(|octet| format!("{:02X}", octet)).collect::<Vec<_>>().join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{EffectiveState, PolicyOwner, PolicySource, QuotaAction, RateLimitPolicy, StoredDevicePolicy, TrafficQuotaPolicy};
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct MemoryBackend {
        state: Rc<RefCell<KernelPolicyState>>,
        wan_bytes: Rc<RefCell<BTreeMap<MacAddress, u64>>>,
        replacements: Rc<Cell<u32>>,
    }

    impl KernelPolicyBackend for MemoryBackend {
        fn read_policy_state(&self) -> Result<KernelPolicyState, String> {
            Ok(self.state.borrow().clone())
        }

        fn replace_policy_state(&mut self, desired: &KernelPolicyState) -> Result<(), String> {
            *self.state.borrow_mut() = desired.clone();
            self.replacements.set(self.replacements.get() + 1);
            Ok(())
        }

        fn read_wan_bytes(&self, mac: &MacAddress) -> Result<u64, String> {
            Ok(*self.wan_bytes.borrow().get(mac).unwrap_or(&0))
        }
    }

    fn snapshot(rate: Option<RateLimitPolicy>, quota: Option<TrafficQuotaPolicy>) -> PolicySnapshot {
        PolicySnapshot {
            schema_version: 1,
            revision: 1,
            policies: vec![StoredDevicePolicy {
                id: "policy-1".to_string(),
                revision: 1,
                source: PolicySource::Quickstart,
                owner: PolicyOwner {
                    product: "quickstart".to_string(),
                    instance: "router-a".to_string(),
                },
                device: DeviceIdentity::Mac {
                    value: "AA:BB:CC:DD:EE:FF".to_string(),
                },
                rate_limit: rate,
                quota,
                state: EffectiveState::Configured,
            }],
        }
    }

    #[test]
    fn maps_download_upload_directions_and_floors_bits_to_bytes() {
        let backend = MemoryBackend::default();
        let state = backend.state.clone();
        let mut plane = NativeDataPlane::new(backend, []);
        plane
            .apply(&snapshot(
                Some(RateLimitPolicy {
                    enabled: true,
                    upload_bits_per_second: 81,
                    download_bits_per_second: 161,
                }),
                None,
            ))
            .unwrap();
        assert_eq!(state.borrow().rate_limits[&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]], [20, 10]);
    }

    #[test]
    fn one_mac_identity_drives_both_ipv4_and_ipv6_kernel_paths() {
        let backend = MemoryBackend::default();
        let mut plane = NativeDataPlane::new(backend, []);
        let desired = snapshot(
            Some(RateLimitPolicy {
                enabled: true,
                upload_bits_per_second: 8_000,
                download_bits_per_second: 0,
            }),
            None,
        );
        plane.apply(&desired).unwrap();
        assert_eq!(plane.backend.read_policy_state().unwrap().rate_limits.len(), 1);
        plane.verify(&desired).unwrap();
    }

    #[test]
    fn installs_only_the_selected_block_quota_period() {
        let backend = MemoryBackend::default();
        backend.wan_bytes.borrow_mut().insert([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 500);
        let mut plane = NativeDataPlane::new(backend, []);
        plane
            .apply(&snapshot(
                None,
                Some(TrafficQuotaPolicy {
                    enabled: true,
                    period: QuotaPeriod::Day,
                    limit_bytes: 1_000,
                    action: QuotaAction::Block,
                }),
            ))
            .unwrap();
        assert_eq!(
            plane.backend.read_policy_state().unwrap().quota_thresholds[&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]],
            [u64::MAX, u64::MAX, 1_500, u64::MAX, u64::MAX, u64::MAX]
        );
    }

    #[test]
    fn replacement_clears_stale_entries_and_restore_reconciles_previous_state() {
        let backend = MemoryBackend::default();
        backend.state.borrow_mut().rate_limits.insert([1; 6], [99, 99]);
        let replacements = backend.replacements.clone();
        let mut plane = NativeDataPlane::new(backend, []);
        let desired = snapshot(
            Some(RateLimitPolicy {
                enabled: true,
                upload_bits_per_second: 8_000,
                download_bits_per_second: 16_000,
            }),
            None,
        );
        plane.apply(&desired).unwrap();
        assert!(!plane.backend.read_policy_state().unwrap().rate_limits.contains_key(&[1; 6]));
        plane
            .restore(&PolicySnapshot {
                schema_version: 1,
                revision: 0,
                policies: Vec::new(),
            })
            .unwrap();
        assert!(plane.backend.read_policy_state().unwrap().rate_limits.is_empty());
        assert_eq!(replacements.get(), 2);
    }

    #[test]
    fn rejects_a_policy_for_the_router_itself() {
        let backend = MemoryBackend::default();
        let router = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut plane = NativeDataPlane::new(backend, [router]);
        let error = plane
            .apply(&snapshot(
                Some(RateLimitPolicy {
                    enabled: true,
                    upload_bits_per_second: 8_000,
                    download_bits_per_second: 8_000,
                }),
                None,
            ))
            .unwrap_err();
        assert!(error.contains("protected router MAC"));
    }

    #[test]
    fn verification_detects_external_kernel_drift() {
        let backend = MemoryBackend::default();
        let state = backend.state.clone();
        let mut plane = NativeDataPlane::new(backend, []);
        let desired = snapshot(
            Some(RateLimitPolicy {
                enabled: true,
                upload_bits_per_second: 8_000,
                download_bits_per_second: 8_000,
            }),
            None,
        );
        plane.apply(&desired).unwrap();
        state.borrow_mut().rate_limits.clear();
        assert!(plane.verify(&desired).unwrap_err().contains("mismatch"));
    }
}
