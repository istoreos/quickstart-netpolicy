use std::fs;
use std::path::Path;

fn command_targets_bandix_interface(command_line: &[u8], interface: &str) -> bool {
    let arguments: Vec<&str> = command_line
        .split(|byte| *byte == 0)
        .filter_map(|part| std::str::from_utf8(part).ok())
        .filter(|part| !part.is_empty())
        .collect();
    let Some(executable) = arguments.first() else {
        return false;
    };
    let executable_name = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(executable);
    if executable_name != "bandix" {
        return false;
    }

    arguments.windows(2).any(|pair| pair[0] == "--iface" && pair[1] == interface)
        || arguments
            .iter()
            .any(|argument| argument.strip_prefix("--iface=") == Some(interface))
}

fn conflicting_bandix_pid(proc_root: &Path, interface: &str) -> Option<u32> {
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
        if command_targets_bandix_interface(&command_line, interface) {
            return Some(pid);
        }
    }
    None
}

pub fn ensure_interface_is_not_owned_by_bandix(interface: &str) -> anyhow::Result<()> {
    if let Some(pid) = conflicting_bandix_pid(Path::new("/proc"), interface) {
        anyhow::bail!(
            "refusing to attach to interface '{}': upstream Bandix process {} already targets it",
            interface,
            pid
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::command_targets_bandix_interface;

    #[test]
    fn detects_upstream_bandix_on_same_interface() {
        assert!(command_targets_bandix_interface(
            b"/usr/bin/bandix\0--iface\0br-lan\0--enable-traffic\0",
            "br-lan"
        ));
        assert!(command_targets_bandix_interface(
            b"bandix\0--iface=br-lan\0--enable-traffic\0",
            "br-lan"
        ));
    }

    #[test]
    fn ignores_other_interfaces_and_our_binary() {
        assert!(!command_targets_bandix_interface(
            b"/usr/bin/bandix\0--iface\0br-guest\0--enable-traffic\0",
            "br-lan"
        ));
        assert!(!command_targets_bandix_interface(
            b"/usr/bin/quickstart-netpolicy\0--iface\0br-lan\0--enable-traffic\0",
            "br-lan"
        ));
    }
}
