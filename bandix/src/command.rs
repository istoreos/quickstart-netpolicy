use crate::device::DeviceManager;

use crate::ebpf::shared::load_shared;
use crate::monitor::{ConnectionModuleContext, DnsModuleContext, ModuleContext, MonitorManager, TrafficModuleContext};
use crate::system::log_startup_info;
use crate::utils::network_utils::get_interface_info;
use crate::web;
use aya::maps::Array;
use clap::{Args, Parser};
use log::info;
use log::LevelFilter;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::signal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcOrder {
    First,
    Default,
    Last,
    Before,
    After,
}

impl TcOrder {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "first" => Some(Self::First),
            "default" => Some(Self::Default),
            "last" => Some(Self::Last),
            "before" => Some(Self::Before),
            "after" => Some(Self::After),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcBackend {
    Auto,
    Tcx,
    Netlink,
}

impl TcBackend {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "tcx" => Some(Self::Tcx),
            "netlink" => Some(Self::Netlink),
            _ => None,
        }
    }
}

/// 所有命令共享的通用参数
#[derive(Debug, Args, Clone)]
pub struct CommonArgs {
    #[clap(skip = uuid::Uuid::new_v4().to_string())]
    pub runtime_epoch: String,
    #[clap(long, default_value = "lan", help = "Logical network bound to this instance")]
    pub network_id: String,
    #[clap(long, default_value = "main", help = "Stable service instance identity")]
    pub instance_id: String,
    #[clap(long, help = "Network interface to monitor (required)")]
    pub iface: String,

    #[clap(long, default_value = "8765", help = "Local control server listening port")]
    pub port: u16,

    #[clap(
        long,
        default_value = "/usr/share/quickstart-netpolicy",
        help = "Data directory (ring files and rate limit configurations will be stored here)"
    )]
    pub data_dir: String,

    #[clap(
        long,
        default_value = "info",
        help = "Log level: trace, debug, info, warn, error (default: info). Web and DNS logs are always at DEBUG level."
    )]
    pub log_level: String,

    #[clap(
        long,
        default_value = "default",
        help = "TC order: first, default, last, before, after"
    )]
    pub tc_order: String,

    #[clap(
        long,
        default_value = "auto",
        help = "TC attach backend: auto, tcx, netlink (default: auto)"
    )]
    pub tc_backend: String,

    #[clap(
        long = "netlink-priority",
        help = "Netlink priority (0..65535, 0 means default). Only used when netlink backend is active"
    )]
    pub netlink_priority: Option<u16>,

    #[clap(
        long = "tcx-anchor-ingress-id",
        help = "TCX ingress anchor program id. Used when tc-order is before/after"
    )]
    pub tcx_anchor_ingress_id: Option<u32>,

    #[clap(
        long = "tcx-anchor-egress-id",
        help = "TCX egress anchor program id. Used when tc-order is before/after"
    )]
    pub tcx_anchor_egress_id: Option<u32>,
}

/// 流量模块参数
#[derive(Debug, Args, Clone)]
#[clap(group = clap::ArgGroup::new("traffic").multiple(false))]
pub struct TrafficArgs {
    #[clap(long, default_value = "false", help = "Enable traffic monitoring module")]
    pub enable_traffic: bool,

    #[clap(
        long,
        default_value = "600",
        help = "Realtime traffic window , Retention duration (seconds)."
    )]
    pub traffic_realtime_window: u32,

    #[clap(
        long,
        default_value = "600",
        help = "Traffic data checkpoint interval (seconds), how often to save accumulator checkpoints to disk. Long-term hourly data is saved immediately at each hour boundary."
    )]
    pub traffic_flush_interval: u32,

    #[clap(
        long,
        default_value = "false",
        help = "Enable traffic history data persistence to disk (disabled by default, data only stored in memory)"
    )]
    pub traffic_enable_storage: bool,

    #[clap(
        long,
        default_value = "",
        help = "Export traffic device list to a remote HTTP endpoint (POST JSON once per second). Empty = disabled."
    )]
    pub traffic_export_url: String,

    #[clap(
        long,
        default_value = "",
        help = "Export device online/offline events to a remote HTTP endpoint (POST JSON on state change). Empty = disabled."
    )]
    pub traffic_event_url: String,

    #[clap(
        long,
        default_value = "",
        help = "Additional local IPv4/IPv6 subnets (comma-separated CIDRs). OpenWrt LAN prefixes are discovered automatically."
    )]
    pub traffic_additional_subnets: String,

    #[clap(
        long,
        default_value = "false",
        help = "Exclude iface interface device (router) from traffic statistics"
    )]
    pub traffic_exclude_iface_device: bool,

    #[clap(
        long,
        default_value = "false",
        help = "Enable periodic neighbor table flush (ip neigh flush). Only takes effect when traffic module is enabled. Flushing affects all programs using the interface."
    )]
    pub traffic_neighbor_flush_enable: bool,

    #[clap(
        long,
        default_value = "600",
        help = "Traffic neighbor flush interval in seconds (default: 600). Only used when traffic-neighbor-flush-enable is true."
    )]
    pub traffic_neighbor_flush_interval: u32,
}

/// DNS 模块参数
#[derive(Debug, Args, Clone)]
pub struct DnsArgs {
    #[clap(long, default_value = "false", help = "Enable DNS monitoring module")]
    pub enable_dns: bool,

    #[clap(
        long,
        default_value = "10000",
        help = "Maximum number of DNS records to keep in memory (default: 10000)"
    )]
    pub dns_max_records: usize,

    #[clap(
        long,
        default_value = "false",
        help = "Enable DNS persistent storage (default: false)"
    )]
    pub dns_enable_storage: bool,

    #[clap(
        long,
        default_value = "900",
        help = "DNS storage flush interval in seconds (default: 900 = 15 minutes)"
    )]
    pub dns_flush_interval: u64,
}

/// 连接模块参数
#[derive(Debug, Args, Clone)]
pub struct ConnectionArgs {
    #[clap(
        long,
        default_value = "false",
        help = "Enable connection statistics monitoring module"
    )]
    pub enable_connection: bool,
}

#[derive(Debug, Parser, Clone)]
#[clap(name = "quickstart-netpolicy")]
#[clap(author = "LinkEase; based on Bandix by timsaya")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Quickstart network policy execution engine for OpenWrt")]
pub struct Options {
    #[clap(flatten)]
    pub common: CommonArgs,

    #[clap(flatten)]
    pub traffic: TrafficArgs,

    #[clap(flatten)]
    pub dns: DnsArgs,

    #[clap(flatten)]
    pub connection: ConnectionArgs,
}

impl Options {
    /// 从通用参数获取接口
    pub fn iface(&self) -> &str {
        &self.common.iface
    }

    /// 从通用参数获取端口
    pub fn port(&self) -> u16 {
        self.common.port
    }

    /// 从通用参数获取数据目录
    pub fn data_dir(&self) -> &str {
        &self.common.data_dir
    }

    /// 从通用参数获取日志级别
    pub fn log_level(&self) -> &str {
        &self.common.log_level
    }

    /// 从通用参数获取 TC 顺序
    pub fn tc_order(&self) -> TcOrder {
        TcOrder::parse(&self.common.tc_order).expect("tc_order must be validated before use")
    }

    /// 从通用参数获取 TC 后端
    pub fn tc_backend(&self) -> TcBackend {
        TcBackend::parse(&self.common.tc_backend).expect("tc_backend must be validated before use")
    }

    pub fn netlink_priority(&self) -> Option<u16> {
        self.common.netlink_priority
    }

    pub fn tcx_anchor_ingress_id(&self) -> Option<u32> {
        self.common.tcx_anchor_ingress_id
    }

    pub fn tcx_anchor_egress_id(&self) -> Option<u32> {
        self.common.tcx_anchor_egress_id
    }

    /// 从流量参数获取启用流量
    pub fn enable_traffic(&self) -> bool {
        self.traffic.enable_traffic
    }

    /// 从流量参数获取流量保留秒数
    pub fn traffic_realtime_window(&self) -> u32 {
        self.traffic.traffic_realtime_window
    }

    /// 从流量参数获取流量持久化间隔秒数
    pub fn traffic_flush_interval(&self) -> u32 {
        self.traffic.traffic_flush_interval
    }

    /// 从流量参数获取流量持久化历史
    pub fn traffic_enable_storage(&self) -> bool {
        self.traffic.traffic_enable_storage
    }

    pub fn traffic_export_url(&self) -> &str {
        &self.traffic.traffic_export_url
    }

    pub fn traffic_event_url(&self) -> &str {
        &self.traffic.traffic_event_url
    }

    pub fn traffic_additional_subnets(&self) -> &str {
        &self.traffic.traffic_additional_subnets
    }

    pub fn traffic_exclude_iface_device(&self) -> bool {
        self.traffic.traffic_exclude_iface_device
    }

    pub fn traffic_neighbor_flush_enable(&self) -> bool {
        self.traffic.traffic_neighbor_flush_enable
    }

    pub fn traffic_neighbor_flush_interval(&self) -> u32 {
        self.traffic.traffic_neighbor_flush_interval
    }

    /// 从 DNS 参数获取启用 DNS
    pub fn enable_dns(&self) -> bool {
        self.dns.enable_dns
    }

    /// 从 DNS 参数获取 DNS 最大记录数
    pub fn dns_max_records(&self) -> usize {
        self.dns.dns_max_records
    }

    /// 从 DNS 参数获取是否启用持久化存储
    pub fn dns_enable_storage(&self) -> bool {
        self.dns.dns_enable_storage
    }

    /// 从 DNS 参数获取刷新间隔（秒）
    pub fn dns_flush_interval(&self) -> u64 {
        self.dns.dns_flush_interval
    }

    /// 从连接参数获取启用连接
    pub fn enable_connection(&self) -> bool {
        self.connection.enable_connection
    }
}

// 解析 CIDR 格式的子网（例如 "192.168.2.0/24"）
pub(crate) fn parse_cidr(cidr: &str) -> Result<([u8; 4], [u8; 4]), anyhow::Error> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!(
            "Invalid CIDR format, expected IP/prefix (e.g., 192.168.2.0/24)"
        ));
    }

    // 解析 IP 地址
    let ip_parts: Vec<&str> = parts[0].split('.').collect();
    if ip_parts.len() != 4 {
        return Err(anyhow::anyhow!("Invalid IP address format"));
    }

    let mut ip = [0u8; 4];
    for (i, part) in ip_parts.iter().enumerate() {
        ip[i] = part
            .parse::<u8>()
            .map_err(|_| anyhow::anyhow!("Invalid IP address octet: {}", part))?;
    }

    // 解析前缀长度
    let prefix_len = parts[1]
        .parse::<u8>()
        .map_err(|_| anyhow::anyhow!("Invalid prefix length: {}", parts[1]))?;

    if prefix_len > 32 {
        return Err(anyhow::anyhow!("Prefix length must be between 0 and 32"));
    }

    // 计算子网掩码
    let mask_bits = if prefix_len == 0 { 0u32 } else { !0u32 << (32 - prefix_len) };

    let subnet_mask = [
        ((mask_bits >> 24) & 0xFF) as u8,
        ((mask_bits >> 16) & 0xFF) as u8,
        ((mask_bits >> 8) & 0xFF) as u8,
        (mask_bits & 0xFF) as u8,
    ];

    // 计算网络地址（IP & 掩码）
    let network_addr = [
        ip[0] & subnet_mask[0],
        ip[1] & subnet_mask[1],
        ip[2] & subnet_mask[2],
        ip[3] & subnet_mask[3],
    ];

    Ok((network_addr, subnet_mask))
}

pub fn build_allowed_ipv4_subnets(subnet_info: &SubnetInfo, additional_subnets: &str) -> Vec<([u8; 4], [u8; 4])> {
    let mut subnets = Vec::new();
    let net: [u8; 4] = [
        subnet_info.interface_ip[0] & subnet_info.subnet_mask[0],
        subnet_info.interface_ip[1] & subnet_info.subnet_mask[1],
        subnet_info.interface_ip[2] & subnet_info.subnet_mask[2],
        subnet_info.interface_ip[3] & subnet_info.subnet_mask[3],
    ];
    subnets.push((net, subnet_info.subnet_mask));
    for cidr in additional_subnets.split(',') {
        let cidr = cidr.trim();
        if cidr.is_empty() {
            continue;
        }
        if let Ok((net, mask)) = parse_cidr(cidr) {
            subnets.push((net, mask));
        }
    }
    subnets
}

// 验证参数
fn validate_arguments(opt: &Options) -> Result<(), anyhow::Error> {
    for name in [&opt.common.network_id, &opt.common.instance_id] {
        if name.is_empty() || name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')) {
            anyhow::bail!("invalid network or instance identity");
        }
    }
    // 检查网络接口是否存在
    if get_interface_info(opt.iface()).is_none() {
        return Err(anyhow::anyhow!("Network interface '{}' does not exist", opt.iface()));
    }

    // 检查端口是否有效（0-65535）
    if opt.port() == 0 {
        return Err(anyhow::anyhow!("Port number cannot be 0"));
    }

    let tc_order = TcOrder::parse(&opt.common.tc_order).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid tc-order: {}. Valid: first, default, last, before, after",
            opt.common.tc_order
        )
    })?;
    let tc_backend = TcBackend::parse(&opt.common.tc_backend)
        .ok_or_else(|| anyhow::anyhow!("Invalid tc-backend: {}. Valid: auto, tcx, netlink", opt.common.tc_backend))?;
    if opt.netlink_priority().is_some() && tc_backend == TcBackend::Tcx {
        anyhow::bail!("--netlink-priority cannot be used with --tc-backend=tcx");
    }
    match tc_order {
        TcOrder::Before | TcOrder::After => {
            let has_ingress = opt.tcx_anchor_ingress_id().is_some();
            let has_egress = opt.tcx_anchor_egress_id().is_some();
            if !has_ingress && !has_egress {
                anyhow::bail!(
                    "anchor program id is required when --tc-order is before/after; use --tcx-anchor-ingress-id/--tcx-anchor-egress-id"
                );
            }
            if tc_backend == TcBackend::Netlink {
                anyhow::bail!("--tc-order=before/after is only supported with tcx backend");
            }
        }
        _ => {
            if opt.tcx_anchor_ingress_id().is_some() || opt.tcx_anchor_egress_id().is_some() {
                anyhow::bail!("--tcx-anchor-ingress-id and --tcx-anchor-egress-id can only be used when --tc-order is before/after");
            }
        }
    }

    // 仅在启用流量模块时验证流量特定参数
    if opt.enable_traffic() {
        if opt.traffic_realtime_window() == 0 {
            return Err(anyhow::anyhow!("traffic_realtime_window must be greater than 0"));
        }

        if opt.traffic_flush_interval() == 0 {
            return Err(anyhow::anyhow!("traffic_flush_interval must be greater than 0"));
        }

        crate::local_networks::parse_additional(opt.traffic_additional_subnets())?;

        if opt.traffic_neighbor_flush_enable() && opt.traffic_neighbor_flush_interval() == 0 {
            return Err(anyhow::anyhow!(
                "traffic_neighbor_flush_interval must be greater than 0 when traffic_neighbor_flush_enable is true"
            ));
        }
    }

    Ok(())
}

// 初始化共享的 eBPF 程序（被流量和 DNS 模块共同使用）
async fn init_shared_ebpf(options: &Options) -> Result<aya::Ebpf, anyhow::Error> {
    load_shared(
        options.iface().to_string(),
        options.tc_order(),
        options.tc_backend(),
        options.netlink_priority(),
        options.tcx_anchor_ingress_id(),
        options.tcx_anchor_egress_id(),
    )
    .await
}

// 子网信息结构体（跨模块共享）
#[derive(Debug, Clone)]
pub struct SubnetInfo {
    pub interface_ip: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub interface_mac: [u8; 6],
    pub ipv6_addresses: Vec<([u8; 16], u8)>,
}

impl SubnetInfo {
    pub fn from_interface(iface: &str) -> Result<Self, anyhow::Error> {
        let interface_info = get_interface_info(iface);

        let (interface_ip, subnet_mask) =
            interface_info.ok_or_else(|| anyhow::anyhow!("Failed to get interface information for '{}'", iface))?;

        let interface_mac = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface))
            .ok()
            .and_then(|content| crate::utils::network_utils::parse_mac_address(content.trim()).ok())
            .unwrap_or([0, 0, 0, 0, 0, 0]);

        let ipv6_addresses = crate::utils::network_utils::get_interface_ipv6_info(iface);

        Ok(SubnetInfo {
            interface_ip,
            subnet_mask,
            interface_mac,
            ipv6_addresses,
        })
    }
}

// Write current interface IPv6 prefixes into the private QSNP_IPV6_NET map.
// 先写新条目再清掉多余槽位，避免刷新期间出现所有网段都未配置的空窗
fn write_ipv6_subnets(
    ipv6_subnet_info: &mut Array<aya::maps::MapData, [u8; 32]>,
    ipv6_addresses: &[([u8; 16], u8)],
) -> Result<(), anyhow::Error> {
    anyhow::ensure!(ipv6_addresses.len() <= 16, "IPv6 prefix capacity exceeded");
    for (idx, (ipv6_addr, prefix_len)) in ipv6_addresses.iter().enumerate() {
        let mut subnet_data = [0u8; 32];
        subnet_data[0..16].copy_from_slice(ipv6_addr);
        subnet_data[16] = *prefix_len;
        subnet_data[17] = 1;
        ipv6_subnet_info.set(idx as u32, &subnet_data, 0)?;

        let addr_type = crate::utils::network_utils::classify_ipv6_address(ipv6_addr);
        log::info!(
            "Configured IPv6 subnet {}: {}/{} [Type: {}, Network: {}]",
            idx,
            crate::utils::network_utils::format_ipv6_with_privacy(ipv6_addr),
            prefix_len,
            addr_type.type_name(),
            addr_type.network_scope()
        );
    }

    for idx in ipv6_addresses.len().min(16)..16 {
        ipv6_subnet_info.set(idx as u32, &[0u8; 32], 0)?;
    }

    Ok(())
}

fn write_local_subnets(
    ipv4: &mut Array<aya::maps::MapData, [u8; 16]>,
    ipv6: &mut Array<aya::maps::MapData, [u8; 32]>,
    local: &crate::local_networks::LocalNetworks,
) -> Result<(), anyhow::Error> {
    anyhow::ensure!(local.ipv4.len() <= 16, "IPv4 prefix capacity exceeded");
    for index in 0..16 {
        let mut row = [0u8; 16];
        if let Some((ip, mask)) = local.ipv4.get(index) {
            row[..4].copy_from_slice(ip); row[4..8].copy_from_slice(mask); row[8] = 1;
        }
        ipv4.set(index as u32, &row, 0)?;
    }
    write_ipv6_subnets(ipv6, &local.ipv6)
}

// 创建模块上下文：加载 eBPF 程序，配置内核映射，并创建上下文对象
async fn create_module_contexts(
    options: &Options,
    subnet_info: &SubnetInfo,
    shared_hostname_bindings: &Arc<Mutex<std::collections::HashMap<[u8; 6], String>>>,
    device_manager: Arc<DeviceManager>,
) -> Result<Vec<ModuleContext>, anyhow::Error> {
    let mut module_contexts = Vec::new();

    // 如果启用了流量或 DNS 模块，则加载共享的 eBPF 程序
    let shared_ebpf = if options.enable_traffic() || options.enable_dns() {
        log::info!("Loading shared eBPF programs (ingress and egress)...");
        let mut ebpf = init_shared_ebpf(options).await?;

        // 如果启用了流量模块，则配置子网信息映射
        if options.enable_traffic() {
            log::info!("Configuring subnet info maps for traffic module...");

            let mut ipv4_subnet_info: Array<_, [u8; 16]> = Array::try_from(ebpf.take_map("QSNP_IPV4_NET").unwrap())?;
            let mut ipv6_subnet_info: Array<_, [u8; 32]> = Array::try_from(ebpf.take_map("QSNP_IPV6_NET").unwrap())?;
            let mut known = crate::local_networks::read(subnet_info, options.traffic_additional_subnets())?;
            write_local_subnets(&mut ipv4_subnet_info, &mut ipv6_subnet_info, &known)?;
            let refresh_iface = options.iface().to_string();
            let additional = options.traffic_additional_subnets().to_string();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    let current = SubnetInfo::from_interface(&refresh_iface)
                        .and_then(|own| crate::local_networks::read(&own, &additional));
                    let update = current.and_then(|current| {
                        if current != known {
                            write_local_subnets(&mut ipv4_subnet_info, &mut ipv6_subnet_info, &current)?;
                            known = current;
                        }
                        Ok(())
                    });
                    if let Err(error) = update {
                        // Continuing with an unknown LAN topology could bill
                        // internal traffic or enforce a WAN rate on another LAN.
                        log::error!("Local topology unavailable, stopping instance: {error}");
                        unsafe { libc::kill(libc::getpid(), libc::SIGTERM); }
                        break;
                    }
                }
            });
        }

        Some(ebpf)
    } else {
        None
    };

    // 配置模块启用标志，如果需要则获取 DNS 映射
    // 这需要对 eBPF 对象的独占访问，因此我们在创建上下文之前完成
    if let Some(mut ebpf) = shared_ebpf {
        // 配置模块启用标志
        log::info!("Configuring module enable flags...");
        let mut module_flags: Array<_, u8> = Array::try_from(
            ebpf.take_map("QSNP_MOD_FLAGS")
                .ok_or_else(|| anyhow::anyhow!("Cannot find QSNP_MOD_FLAGS map"))?,
        )?;

        // 设置traffic module flag (index 0)
        let traffic_flag = if options.enable_traffic() { 1u8 } else { 0u8 };
        module_flags.set(0, &traffic_flag, 0)?;
        log::info!("Traffic module enabled: {}", traffic_flag != 0);

        // 设置DNS module flag (index 1)
        let dns_flag = if options.enable_dns() { 1u8 } else { 0u8 };
        module_flags.set(1, &dns_flag, 0)?;
        log::info!("DNS module enabled: {}", dns_flag != 0);

        let dns_map = if options.enable_dns() {
            // Acquire the private DNS ring map before wrapping the eBPF object in Arc.
            // 这是必要的，因为 take_map 需要独占访问
            log::info!("Acquiring DNS RingBuf map...");
            Some(
                ebpf.take_map("QSNP_DNS_DATA")
                    .ok_or_else(|| anyhow::anyhow!("Cannot find QSNP_DNS_DATA map. Make sure DNS eBPF programs are loaded correctly."))?,
            )
        } else {
            None
        };

        // 现在包装到 Arc 中，以便两个模块可以共享
        let shared_ebpf_arc = Arc::new(ebpf);

        // 初始化流量模块
        if options.enable_traffic() {
            log::info!("Initializing traffic module...");

            // 创建对共享 eBPF 对象的引用
            let ingress = Arc::clone(&shared_ebpf_arc);
            let egress = Arc::clone(&shared_ebpf_arc);

            // 创建流量模块上下文（使用共享的 device_manager）
            let mut traffic_ctx = TrafficModuleContext::new(options.clone(), ingress, egress, Arc::clone(&device_manager));
            traffic_ctx.hostname_bindings = Arc::clone(shared_hostname_bindings);

            module_contexts.push(ModuleContext::Traffic(traffic_ctx));
        }

        // 初始化 DNS 模块
        if options.enable_dns() {
            log::info!("Initializing DNS module...");

            // 创建对共享 eBPF 对象的引用
            let ingress = Arc::clone(&shared_ebpf_arc);
            let egress = Arc::clone(&shared_ebpf_arc);

            // 使用预获取的映射创建 DNS 模块上下文
            let dns_ctx = DnsModuleContext::new_with_map(
                options.clone(),
                ingress,
                egress,
                dns_map.unwrap(),
                Arc::clone(shared_hostname_bindings),
            );
            module_contexts.push(ModuleContext::Dns(dns_ctx));
        }
    }

    // 初始化连接模块
    if options.enable_connection() {
        log::info!("Initializing connection module...");

        // 创建连接模块上下文
        let connection_ctx = ConnectionModuleContext::new(
            options.clone(),
            Arc::clone(shared_hostname_bindings),
            subnet_info.interface_ip,
            subnet_info.subnet_mask,
        );
        module_contexts.push(ModuleContext::Connection(connection_ctx));
    }

    Ok(module_contexts)
}

// 启动主机名刷新任务：定期从 ubus 更新主机名绑定
fn start_hostname_refresh_task(
    shared_hostname_bindings: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<[u8; 6], String>>>,
    options: Options,
    shutdown_notify: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // 从 ubus 加载主机名绑定（如果 ubus 不可用则静默失败）
                    if let Ok(ubus_bindings) = crate::storage::hostname::load_hostname_from_ubus() {
                        let mut bindings_map = shared_hostname_bindings.lock().unwrap();
                        let mut updated_count = 0;

                        // 加载保存的绑定以检查优先级
                        let saved_bindings = crate::storage::hostname::load_hostname_bindings(options.data_dir())
                            .unwrap_or_default();
                        let saved_macs: std::collections::HashSet<[u8; 6]> =
                            saved_bindings.iter().map(|(mac, _)| *mac).collect();

                        for (mac, hostname) in ubus_bindings {
                            // 仅在未手动设置时更新（不在保存的绑定中）
                            if !saved_macs.contains(&mac) {
                                if let Some(existing) = bindings_map.get(&mac) {
                                    if existing != &hostname {
                                        bindings_map.insert(mac, hostname);
                                        updated_count += 1;
                                    }
                                } else {
                                    bindings_map.insert(mac, hostname);
                                    updated_count += 1;
                                }
                            }
                        }

                        if updated_count > 0 {
                            log::debug!("Updated {} hostname bindings from ubus", updated_count);
                        }
                    }
                }
                _ = shutdown_notify.notified() => {
                    log::info!("Hostname refresh task received shutdown signal, stopping...");
                    break;
                }
            }
        }
    })
}

fn start_neighbor_flush_task(iface: String, interval_secs: u64, shutdown_notify: Arc<tokio::sync::Notify>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if std::process::Command::new("ip")
                        .args(["-4", "neigh", "flush", "dev", &iface])
                        .output()
                        .map(|o| !o.status.success())
                        .unwrap_or(true)
                    {
                        log::warn!("ip -4 neigh flush dev {} failed", iface);
                    }
                    if std::process::Command::new("ip")
                        .args(["-6", "neigh", "flush", "dev", &iface])
                        .output()
                        .map(|o| !o.status.success())
                        .unwrap_or(true)
                    {
                        log::warn!("ip -6 neigh flush dev {} failed", iface);
                    }
                    log::debug!("Neighbor table flushed for {}", iface);
                }
                _ = shutdown_notify.notified() => {
                    log::info!("Neighbor flush task received shutdown signal, stopping...");
                    break;
                }
            }
        }
    })
}

// 运行服务
async fn run_service(options: &Options, _engine_lease: crate::engine_guard::EngineLease) -> Result<(), anyhow::Error> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, options.port())).await?;
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let shutdown_notify_clone = shutdown_notify.clone();
    let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();

    let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    tokio::spawn(async move {
        tokio::select! { _ = signal::ctrl_c() => {}, _ = terminate.recv() => {} }
        info!("Received shutdown signal, gracefully shutting down...");
        shutdown_flag_clone.store(true, std::sync::atomic::Ordering::Relaxed);
        shutdown_notify_clone.notify_waiters();
    });

    let subnet_info = SubnetInfo::from_interface(options.iface())?;

    let hostname_bindings_vec = crate::storage::hostname::load_hostname_bindings(options.data_dir()).unwrap_or_default();
    let shared_hostname_bindings: Arc<Mutex<std::collections::HashMap<[u8; 6], String>>> =
        Arc::new(Mutex::new(hostname_bindings_vec.into_iter().collect()));

    let allowed_ipv4_subnets = build_allowed_ipv4_subnets(&subnet_info, options.traffic_additional_subnets());
    let device_manager = Arc::new(DeviceManager::new(
        options.iface().to_string(),
        subnet_info.clone(),
        allowed_ipv4_subnets,
        Arc::clone(&shared_hostname_bindings),
        options.traffic_exclude_iface_device(),
    ));

    // 首次刷新邻居表，获取局域网设备
    if let Err(e) = device_manager.refresh_devices().await {
        log::warn!("Failed to load initial devices: {}", e);
    }

    // 启动设备管理器的后台任务
    let event_url = options.traffic_event_url().trim();
    let event_url = if event_url.is_empty() { None } else { Some(event_url.to_string()) };
    let device_refresh_task =
        Arc::clone(&device_manager).start_background_task(Duration::from_secs(30), shutdown_notify.clone(), event_url);

    // 创建模块上下文：加载 eBPF 程序并配置内核映射
    let module_contexts = create_module_contexts(options, &subnet_info, &shared_hostname_bindings, Arc::clone(&device_manager)).await?;

    // 初始化模块
    let mut monitor_manager = MonitorManager::from_contexts(&module_contexts);
    monitor_manager.init_modules(&module_contexts).await?;

    let policy_engine = module_contexts.iter().find_map(|context| match context {
        ModuleContext::Traffic(traffic) => traffic.ingress_ebpf.as_ref().map(|ebpf| {
            let backend = crate::policy::dataplane::AyaKernelPolicyBackend::new(Arc::clone(ebpf));
            let data_plane = crate::policy::dataplane::NativeDataPlane::new(backend, [subnet_info.interface_mac]);
            crate::policy::transaction::NativePolicyEngine::open(
                crate::policy::store::PolicyStore::new(options.data_dir()),
                crate::policy::transaction::TransactionJournal::new(options.data_dir()),
                data_plane,
                options.iface(),
            )
            .map(|engine| engine.with_context(&options.common.network_id, &options.common.instance_id).with_runtime_epoch(&options.common.runtime_epoch))
        }),
        _ => None,
    });

    // 启动 Web 服务器
    let mut api_router = monitor_manager.get_api_router().clone();
    if let Some(engine) = policy_engine {
        api_router.set_policy_engine(Arc::new(Mutex::new(
            Box::new(engine?) as Box<dyn crate::policy::TrafficPolicyEngine + Send>
        )));
    }
    let shutdown_notify_for_web = shutdown_notify.clone();
    let web_task = tokio::spawn(async move {
        if let Err(e) = web::start_server(listener, api_router, shutdown_notify_for_web).await {
            log::error!("Web server error: {}", e);
        }
    });

    // 启动主机名刷新任务
    let hostname_refresh_task =
        start_hostname_refresh_task(Arc::clone(&shared_hostname_bindings), options.clone(), shutdown_notify.clone());

    // 通过 MonitorManager 为所有模块启动内部循环
    let mut tasks = monitor_manager.start_modules(module_contexts, shutdown_notify.clone()).await?;

    tasks.push(web_task);
    tasks.push(hostname_refresh_task);
    tasks.push(device_refresh_task);
    tasks.push(crate::engine_guard::start_conflict_monitor(
        options.iface().to_string(),
        shutdown_notify.clone(),
    ));

    if options.enable_traffic() && options.traffic_neighbor_flush_enable() {
        let neighbor_flush_task = start_neighbor_flush_task(
            options.iface().to_string(),
            options.traffic_neighbor_flush_interval() as u64,
            shutdown_notify.clone(),
        );
        tasks.push(neighbor_flush_task);
    }

    // 等待关闭信号
    if shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
        shutdown_notify.notify_waiters();
    } else {
        shutdown_notify.notified().await;
    }
    info!("Stopping all modules...");

    // Bound shutdown even if a task missed the early startup signal. Aborting
    // and joining drops this process's Aya links before the interface lease.
    let joined = tokio::time::timeout(Duration::from_secs(5), async {
        for task in &mut tasks {
            if let Err(error) = task.await {
                log::error!("Module task error: {}", error);
            }
        }
    })
    .await;
    if joined.is_err() {
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }

    info!("All modules stopped, program exiting");

    Ok(())
}

pub async fn run(options: Options) -> Result<(), anyhow::Error> {
    validate_arguments(&options)?;

    let log_level = match options.log_level().to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid log level: {}. Valid values: trace, debug, info, warn, error",
                options.log_level()
            ));
        }
    };

    env_logger::Builder::new()
        .filter(None, log_level)
        .filter_module("aya::bpf", LevelFilter::Error)
        .target(env_logger::Target::Stdout)
        .init();

    log_startup_info(&options);

    // 检查是否至少启用了 一个模块
    if !options.enable_traffic() && !options.enable_dns() && !options.enable_connection() {
        return Err(anyhow::anyhow!(
            "No monitoring modules enabled. At least one module must be enabled: --enable-traffic, --enable-dns, or --enable-connection"
        ));
    }

    if options.enable_traffic() || options.enable_dns() {
        crate::engine_guard::ensure_no_external_engine(options.iface())?;
    }

    let _data_lease = crate::engine_guard::acquire_data_directory(options.data_dir(), &options.common.network_id, &options.common.instance_id)?;
    let engine_lease = crate::engine_guard::EngineLease::acquire(options.iface())?;
    run_service(&options, engine_lease).await?;

    Ok(())
}
