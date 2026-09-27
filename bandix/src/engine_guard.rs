use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
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
}

pub struct EngineLease {
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
        let path = root.join(format!("{}.lease", interface));
        for _ in 0..2 {
            let token = uuid::Uuid::new_v4().to_string();
            let record = LeaseRecord {
                product: "quickstart-netpolicy".to_string(),
                interface: interface.to_string(),
                pid: std::process::id(),
                token: token.clone(),
            };
            match OpenOptions::new().create_new(true).write(true).open(&path) {
                Ok(mut file) => {
                    let payload = serde_json::to_vec(&record)?;
                    file.write_all(&payload)?;
                    file.sync_all()?;
                    return Ok(Self { path, token });
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    let existing = fs::read(&path)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<LeaseRecord>(&bytes).ok());
                    if let Some(existing) = existing {
                        if proc_root.join(existing.pid.to_string()).exists() {
                            anyhow::bail!(
                                "interface '{}' is already owned by {} process {}",
                                interface,
                                existing.product,
                                existing.pid
                            );
                        }
                    }
                    fs::remove_file(&path)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("failed to acquire interface '{}' lease", interface)
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
            let _ = fs::remove_file(&self.path);
        }
    }
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
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
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
}
