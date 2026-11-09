use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

const LEASE_ROOT: &str = "/var/run/quickstart-netpolicy";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConflict {
    pub product: String,
    pub pid: Option<u32>,
    pub interface: String,
}

impl std::fmt::Display for EngineConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.pid {
            Some(pid) => write!(
                formatter,
                "{} process {} already targets interface '{}'",
                self.product, pid, self.interface
            ),
            None => write!(formatter, "{} already targets interface '{}'", self.product, self.interface),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LeaseRecord {
    product: String,
    interface: String,
    pid: u32,
    token: String,
    #[serde(default)]
    locking: bool,
}

pub struct EngineLease {
    file: File,
    path: PathBuf,
    token: String,
}

impl EngineLease {
    pub fn acquire(interface: &str) -> anyhow::Result<Self> {
        Self::acquire_at(Path::new(LEASE_ROOT), Path::new("/proc"), interface)
    }

    fn acquire_at(root: &Path, proc_root: &Path, interface: &str) -> anyhow::Result<Self> {
        validate_interface(interface)?;
        fs::create_dir_all(root)?;
        let registry = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join(".registry.lock"))?;
        // Serialize the short discovery/acquire step. Different LANs starting
        // together are valid and must not become transient engine conflicts.
        if unsafe { libc::flock(registry.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        for entry in fs::read_dir(root)?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(other) = name.strip_suffix(".lease") else { continue };
            if other == interface || !interfaces_overlap(interface, other) {
                continue;
            }
            let occupied = exclusive_file(&entry.path()).is_err();
            let legacy_live = fs::read(entry.path())
                .ok()
                .and_then(|bytes| serde_json::from_slice::<LeaseRecord>(&bytes).ok())
                .is_some_and(|record| !record.locking && legacy_lease_is_live(proc_root, &record));
            if occupied || legacy_live {
                anyhow::bail!("interface '{}' overlaps active engine interface '{}'", interface, other);
            }
        }
        let path = root.join(format!("{}.lease", interface));
        let mut file = exclusive_file(&path)?;
        let mut existing_bytes = Vec::new();
        file.read_to_end(&mut existing_bytes)?;
        if let Ok(existing) = serde_json::from_slice::<LeaseRecord>(&existing_bytes) {
            // Compatibility with a previous release that did not hold flock.
            if !existing.locking && legacy_lease_is_live(proc_root, &existing) {
                anyhow::bail!("interface '{}' is owned by legacy process {}", interface, existing.pid);
            }
        }
        let token = uuid::Uuid::new_v4().to_string();
        let record = LeaseRecord {
            product: "quickstart-netpolicy".into(),
            interface: interface.into(),
            pid: std::process::id(),
            token: token.clone(),
            locking: true,
        };
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&serde_json::to_vec(&record)?)?;
        file.sync_all()?;
        Ok(Self { file, path, token })
    }
}

impl Drop for EngineLease {
    fn drop(&mut self) {
        let owned = fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<LeaseRecord>(&bytes).ok())
            .map(|record| record.token == self.token)
            .unwrap_or(false);
        if owned {
            let _ = self.file.set_len(0);
        }
    }
}

// Lock files are never unlinked: removing a locked inode lets another process
// create and lock a new inode at the same pathname.
fn exclusive_file(path: &Path) -> anyhow::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        anyhow::bail!("resource '{}' is already owned by another engine", path.display());
    }
    Ok(file)
}

#[derive(Serialize, Deserialize)]
struct DataScope {
    schema_version: u32,
    network_id: String,
}

pub fn acquire_data_directory(data_dir: &str, network_id: &str, instance_id: &str) -> anyhow::Result<File> {
    fs::create_dir_all(data_dir)?;
    let canonical = fs::canonicalize(data_dir)?;
    let lease = exclusive_file(&canonical.join(".engine.lock"))?;
    let marker = canonical.join(".network-scope.json");
    match fs::read(&marker) {
        Ok(bytes) => {
            let stored: DataScope = serde_json::from_slice(&bytes)?;
            if stored.schema_version != 1 || stored.network_id != network_id {
                anyhow::bail!("data directory belongs to another network; use a separate directory");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let occupied = fs::read_dir(&canonical)?.any(|entry| entry.map(|item| item.file_name() != ".engine.lock").unwrap_or(true));
            // Only the original lan/main contract can adopt pre-scope data.
            if occupied && (network_id != "lan" || instance_id != "main") {
                anyhow::bail!("unscoped existing data cannot be assigned to an additional LAN");
            }
            let temporary = canonical.join(format!(".network-scope-{}.tmp", uuid::Uuid::new_v4()));
            let mut file = OpenOptions::new().create_new(true).write(true).open(&temporary)?;
            file.write_all(&serde_json::to_vec(&DataScope { schema_version: 1, network_id: network_id.into() })?)?;
            file.sync_all()?;
            fs::rename(&temporary, &marker)?;
            File::open(&canonical)?.sync_all()?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(lease)
}

pub fn interface_index(interface: &str) -> u32 {
    fs::read_to_string(format!("/sys/class/net/{}/ifindex", interface))
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

fn lower_interfaces(interface: &str, seen: &mut BTreeSet<String>) {
    if !seen.insert(interface.into()) || seen.len() > 64 {
        return;
    }
    if let Ok(entries) = fs::read_dir(format!("/sys/class/net/{}", interface)) {
        for entry in entries.flatten() {
            if let Some(lower) = entry.file_name().to_string_lossy().strip_prefix("lower_") {
                lower_interfaces(lower, seen);
            }
        }
    }
    if let Ok(entries) = fs::read_dir(format!("/sys/class/net/{}/brif", interface)) {
        for entry in entries.flatten() {
            lower_interfaces(&entry.file_name().to_string_lossy(), seen);
        }
    }
}

fn interfaces_overlap(left: &str, right: &str) -> bool {
    let mut lower = BTreeSet::new();
    lower_interfaces(left, &mut lower);
    if lower.contains(right) {
        return true;
    }
    lower.clear();
    lower_interfaces(right, &mut lower);
    lower.contains(left)
}

fn legacy_lease_is_live(proc_root: &Path, record: &LeaseRecord) -> bool {
    let path = proc_root.join(record.pid.to_string());
    let bytes = match fs::read(path.join("cmdline")) {
        Ok(bytes) => bytes,
        Err(_) => return path.exists(),
    };
    let args: Vec<_> = bytes
        .split(|b| *b == 0)
        .filter_map(|b| std::str::from_utf8(b).ok())
        .filter(|s| !s.is_empty())
        .collect();
    args.first()
        .is_some_and(|arg| Path::new(arg).file_name().is_some_and(|name| name == "quickstart-netpolicy"))
        && (args.windows(2).any(|pair| pair[0] == "--iface" && pair[1] == record.interface)
            || args.iter().any(|arg| arg.strip_prefix("--iface=") == Some(&record.interface)))
}

fn validate_interface(interface: &str) -> anyhow::Result<()> {
    if interface.is_empty()
        || interface.len() > 32
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        anyhow::bail!("invalid interface name '{}'", interface);
    }
    Ok(())
}

fn process_target(command_line: &[u8], interface: &str) -> Option<&'static str> {
    let arguments: Vec<&str> = command_line
        .split(|byte| *byte == 0)
        .filter_map(|part| std::str::from_utf8(part).ok())
        .filter(|part| !part.is_empty())
        .collect();
    let executable = arguments.first()?;
    let executable_name = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(executable);
    let product = match executable_name {
        "bandix" => "Bandix",
        "eqos" | "eqosd" => "eQoS",
        _ => return None,
    };
    let targets_interface = arguments.windows(2).any(|pair| pair[0] == "--iface" && pair[1] == interface)
        || arguments
            .iter()
            .any(|argument| argument.strip_prefix("--iface=") == Some(interface));
    targets_interface.then_some(product)
}

fn external_engine_conflict(proc_root: &Path, interface: &str) -> Option<EngineConflict> {
    let current_pid = std::process::id();
    for entry in fs::read_dir(proc_root).ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        if pid == current_pid {
            continue;
        }
        let Ok(command_line) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        if let Some(product) = process_target(&command_line, interface) {
            return Some(EngineConflict {
                product: product.to_string(),
                pid: Some(pid),
                interface: interface.to_string(),
            });
        }
    }
    None
}

pub fn ensure_no_external_engine(interface: &str) -> anyhow::Result<()> {
    if let Some(conflict) = external_engine_conflict(Path::new("/proc"), interface) {
        anyhow::bail!("refusing to attach: {}", conflict);
    }
    Ok(())
}

pub fn start_conflict_monitor(interface: String, shutdown: std::sync::Arc<tokio::sync::Notify>) -> tokio::task::JoinHandle<()> {
    let original_index = interface_index(&interface);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if original_index != 0 && interface_index(&interface) != original_index {
                        log::error!("interface identity changed; stopping this instance");
                        shutdown.notify_waiters(); break;
                    }
                    if let Some(conflict) = external_engine_conflict(Path::new("/proc"), &interface) {
                        log::error!("runtime traffic-engine conflict detected; stopping safely: {}", conflict);
                        shutdown.notify_waiters();
                        break;
                    }
                }
                _ = shutdown.notified() => break,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("qsnp-guard-{}-{}", name, uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn data_scope_survives_restart_and_rejects_network_rebinding() {
        let root = directory("scope");
        drop(acquire_data_directory(root.to_str().unwrap(), "office", "office").unwrap());
        drop(acquire_data_directory(root.to_str().unwrap(), "office", "renamed-instance").unwrap());
        assert!(acquire_data_directory(root.to_str().unwrap(), "guest", "guest").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_legacy_default_can_adopt_nonempty_unscoped_data() {
        let root = directory("legacy-scope");
        fs::write(root.join("policy.json"), "existing").unwrap();
        assert!(acquire_data_directory(root.to_str().unwrap(), "office", "office").is_err());
        drop(acquire_data_directory(root.to_str().unwrap(), "lan", "main").unwrap());
        assert_eq!(fs::read_to_string(root.join("policy.json")).unwrap(), "existing");
        fs::write(root.join(".network-scope.json"), "broken").unwrap();
        assert!(acquire_data_directory(root.to_str().unwrap(), "lan", "main").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn detects_bandix_and_eqos_only_on_the_same_interface() {
        assert_eq!(process_target(b"/usr/bin/bandix\0--iface\0br-lan\0", "br-lan"), Some("Bandix"));
        assert_eq!(process_target(b"eqosd\0--iface=br-lan\0", "br-lan"), Some("eQoS"));
        assert_eq!(process_target(b"bandix\0--iface=br-guest\0", "br-lan"), None);
        assert_eq!(process_target(b"quickstart-netpolicy\0--iface=br-lan\0", "br-lan"), None);
    }

    #[test]
    fn live_lease_blocks_same_interface_but_not_another_interface() {
        let root = directory("live");
        let proc_root = root.join("proc");
        fs::create_dir_all(proc_root.join(std::process::id().to_string())).unwrap();
        let lease = EngineLease::acquire_at(&root, &proc_root, "br-lan").unwrap();
        assert!(EngineLease::acquire_at(&root, &proc_root, "br-lan").is_err());
        let other = EngineLease::acquire_at(&root, &proc_root, "br-guest").unwrap();
        drop(other);
        drop(lease);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_lease_is_reclaimed_and_drop_does_not_remove_a_replaced_lease() {
        let root = directory("stale");
        let proc_root = root.join("proc");
        fs::create_dir_all(&proc_root).unwrap();
        let path = root.join("br-lan.lease");
        fs::write(
            &path,
            serde_json::to_vec(&LeaseRecord {
                product: "quickstart-netpolicy".to_string(),
                interface: "br-lan".to_string(),
                pid: 999_999,
                token: "stale".to_string(),
                locking: false,
            })
            .unwrap(),
        )
        .unwrap();
        let lease = EngineLease::acquire_at(&root, &proc_root, "br-lan").unwrap();
        fs::write(
            &path,
            serde_json::to_vec(&LeaseRecord {
                product: "replacement".to_string(),
                interface: "br-lan".to_string(),
                pid: 1,
                token: "other".to_string(),
                locking: false,
            })
            .unwrap(),
        )
        .unwrap();
        drop(lease);
        assert!(path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scans_processes_for_runtime_conflicts() {
        let root = directory("proc");
        fs::create_dir_all(root.join("4242")).unwrap();
        fs::write(root.join("4242/cmdline"), b"/usr/bin/bandix\0--iface\0br-lan\0").unwrap();
        assert_eq!(external_engine_conflict(&root, "br-lan").unwrap().pid, Some(4242));
        assert!(external_engine_conflict(&root, "br-guest").is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_directory_lock_rejects_aliases_and_releases_on_drop() {
        let root = directory("data-lock");
        let data = root.join("data");
        let lease = acquire_data_directory(data.to_str().unwrap(), "lan", "main").unwrap();
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&data, &alias).unwrap();
        assert!(acquire_data_directory(alias.to_str().unwrap(), "lan", "main").is_err());
        drop(lease);
        assert!(acquire_data_directory(alias.to_str().unwrap(), "lan", "main").is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_pid_reuse_does_not_claim_an_unrelated_process() {
        let root = directory("pid-reuse");
        fs::create_dir_all(root.join("123")).unwrap();
        let record = LeaseRecord {
            product: "quickstart-netpolicy".into(),
            interface: "br-lan".into(),
            pid: 123,
            token: "legacy".into(),
            locking: false,
        };
        fs::write(root.join("123/cmdline"), b"/bin/unrelated\0--iface\0br-lan\0").unwrap();
        assert!(!legacy_lease_is_live(&root, &record));
        fs::write(
            root.join("123/cmdline"),
            b"/opt/current/quickstart-netpolicy\0--iface\0br-lan\0",
        )
        .unwrap();
        assert!(legacy_lease_is_live(&root, &record));
        fs::remove_dir_all(root).unwrap();
    }
}
