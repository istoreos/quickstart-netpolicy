use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

// ============================================================================
// Traffic Monitoring Maps
// ============================================================================

// record traffic stats of a mac address, [local send bytes, local receive bytes, wide send bytes, wide receive bytes]
#[map]
pub static QSNP_TRAFFIC: HashMap<[u8; 6], [u64; 4]> = HashMap::with_max_entries(1024, 0);

// ============================================================================
// Rate Limiting Maps
// ============================================================================

// rate limit: [download limit(bytes/s), upload limit(bytes/s)]
#[map]
pub static QSNP_RATE_LIMIT: HashMap<[u8; 6], [u64; 2]> = HashMap::with_max_entries(1024, 0);

// Devices whose WAN traffic quota has been exhausted. A present non-zero
// value blocks both upload and download while leaving LAN traffic untouched.
#[map]
pub static QSNP_QUOTA_BLK: HashMap<[u8; 6], u8> = HashMap::with_max_entries(1024, 0);

// Absolute WAN byte thresholds for minute/hour/day/week/month/lifetime quotas.
// u64::MAX means unlimited. Once the device's cumulative WAN byte counter
// reaches any configured threshold, TC drops subsequent packets immediately.
#[map]
pub static QSNP_QUOTA_LIM: HashMap<[u8; 6], [u64; 6]> = HashMap::with_max_entries(1024, 0);

// rate bucket status: [download token number, upload token number, last update time(ns)]
#[map]
pub static QSNP_BUCKETS: HashMap<[u8; 6], [u64; 3]> = HashMap::with_max_entries(1024, 0);
