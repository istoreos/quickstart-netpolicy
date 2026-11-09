//! Locality for WAN accounting, independent of device admission/ownership.
//! This reads topology only: it never changes network, DHCP or firewall config.
use crate::command::{parse_cidr, SubnetInfo};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{collections::BTreeSet, net::IpAddr, process::Command};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LocalNetworks {
    pub ipv4: Vec<([u8; 4], [u8; 4])>,
    pub ipv6: Vec<([u8; 16], u8)>,
}

fn query(object: &str, method: &str, payload: &str) -> Result<Value> {
    let output = Command::new("ubus")
        .args(["-t", "3", "-S", "call", object, method, payload])
        .output()?;
    if !output.status.success() {
        bail!("local network topology query failed: {object}");
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

pub fn read(own: &SubnetInfo, additional: &str) -> Result<LocalNetworks> {
    let mut result = LocalNetworks::default();
    if own.subnet_mask != [0; 4] {
        result.ipv4.push((own.interface_ip, own.subnet_mask));
    }
    result.ipv6 = own.ipv6_addresses.clone();
    let explicit = parse_additional(additional)?;
    result.ipv4.extend(explicit.ipv4);
    result.ipv6.extend(explicit.ipv6);
    // Standalone Linux retains the explicit interface/CLI topology. On OpenWrt,
    // a failed ubus read must not silently turn another LAN into WAN traffic.
    if std::path::Path::new("/etc/openwrt_release").exists() {
        let firewall = query("uci", "get", r#"{"config":"firewall"}"#)?;
        let runtime = query("network.interface", "dump", "{}")?;
        let dhcp = query("uci", "get", r#"{"config":"dhcp"}"#)?;
        result.extend_topology(&firewall, &runtime, Some(&dhcp))?;
    }
    result.normalize()?;
    Ok(result)
}

pub fn parse_additional(additional: &str) -> Result<LocalNetworks> {
    let mut result = LocalNetworks::default();
    for cidr in additional.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        if cidr.contains(':') {
            let (address, prefix) = cidr.split_once('/').context("IPv6 subnet requires prefix")?;
            result
                .ipv6
                .push((address.parse::<std::net::Ipv6Addr>()?.octets(), prefix.parse()?));
        } else {
            result.ipv4.push(parse_cidr(cidr)?);
        }
    }
    result.normalize()?;
    Ok(result)
}

impl LocalNetworks {
    fn extend_topology(&mut self, firewall: &Value, runtime: &Value, dhcp: Option<&Value>) -> Result<()> {
        let mut excluded = BTreeSet::from([
            "wan".to_string(),
            "wan6".to_string(),
            "loopback".to_string(),
            "docker".to_string(),
        ]);
        let sections = firewall["values"].as_object().context("missing firewall topology")?;
        for section in sections.values() {
            if section[".type"] != "zone" {
                continue;
            }
            let networks: Vec<&str> = match &section["network"] {
                Value::Array(v) => v.iter().filter_map(Value::as_str).collect(),
                Value::String(v) => v.split_whitespace().collect(),
                _ => vec![],
            };
            let name = section["name"].as_str().unwrap_or_default();
            let incoming = sections.values().any(|item| {
                item[".type"] == "forwarding"
                    && item["dest"] == name
                    && item["src"].as_str().is_some_and(|src| !src.is_empty() && src != name)
            });
            let reject = |value: &Value| matches!(value.as_str(), Some("REJECT" | "DROP"));
            let default_route = runtime["interface"].as_array().into_iter().flatten().any(|item| {
                networks.contains(&item["interface"].as_str().unwrap_or_default())
                    && item["route"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|route| route["mask"] == 0 && matches!(route["target"].as_str(), Some("0.0.0.0" | "::")))
            });
            // Same positive role evidence as the management resolver. Do not
            // infer WAN from a default route on a bypass LAN alone.
            let local_dhcp = dhcp.and_then(|value| value["values"].as_object()).is_some_and(|values| {
                values.values().any(|item| {
                    item[".type"] == "dhcp" && item["ignore"] != "1" && networks.contains(&item["interface"].as_str().unwrap_or_default())
                })
            });
            let renamed_uplink = !local_dhcp
                && name != "lan"
                && !networks.contains(&"lan")
                && incoming
                && reject(&section["input"])
                && reject(&section["forward"])
                && default_route;
            if name == "wan" || name == "docker" || networks.iter().any(|n| *n == "wan" || *n == "wan6") || renamed_uplink {
                excluded.extend(networks.into_iter().map(str::to_owned));
            }
        }
        for network in runtime["interface"].as_array().context("missing runtime interfaces")? {
            let name = network["interface"].as_str().unwrap_or_default();
            if excluded.contains(name) || network["up"] != true {
                continue;
            }
            // Match supported LAN protocols, including an externally served LAN in
            // bypass mode. Uplinks are excluded by identity/zone above.
            if !matches!(network["proto"].as_str(), Some("static" | "none" | "dhcp" | "dhcpv6")) {
                continue;
            }
            for field in ["ipv4-address", "ipv6-address", "ipv6-prefix-assignment"] {
                for address in network[field].as_array().into_iter().flatten() {
                    let ip: IpAddr = address["address"].as_str().context("missing local address")?.parse()?;
                    let mask = address["mask"].as_u64().context("missing local prefix")?;
                    match ip {
                        IpAddr::V4(ip) if mask > 0 && mask <= 32 => {
                            self.ipv4.push(parse_cidr(&format!("{ip}/{mask}"))?);
                        }
                        IpAddr::V6(ip) if mask > 0 && mask <= 128 => {
                            self.ipv6.push((ip.octets(), mask as u8));
                        }
                        _ => bail!("invalid local network prefix"),
                    }
                }
            }
        }
        Ok(())
    }
    fn normalize(&mut self) -> Result<()> {
        for (ip, mask) in &mut self.ipv4 {
            for i in 0..4 {
                ip[i] &= mask[i];
            }
        }
        for (ip, prefix) in &mut self.ipv6 {
            if *prefix == 0 || *prefix > 128 {
                bail!("invalid IPv6 prefix");
            }
            let mask = u128::MAX << (128 - *prefix);
            *ip = (u128::from_be_bytes(*ip) & mask).to_be_bytes();
        }
        self.ipv4.sort();
        self.ipv4.dedup();
        self.ipv6.sort();
        self.ipv6.dedup();
        if self.ipv4.len() > 16 || self.ipv6.len() > 16 {
            bail!("local network prefix capacity exceeded (16 per family)");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn other_lan_is_local_but_wan_is_not() {
        let fw = json!({"values":{"a":{".type":"zone","name":"lan","network":["lan","office"]},"b":{".type":"zone","name":"wan","network":["wan","uplink"]}}});
        let interfaces = json!({"interface":[
         {"interface":"office","up":true,"proto":"dhcp","ipv4-address":[{"address":"192.168.80.1","mask":24}],"ipv6-prefix-assignment":[{"address":"fd80::","mask":64}]},
         {"interface":"uplink","up":true,"proto":"dhcp","ipv4-address":[{"address":"192.168.30.7","mask":24}]},
         {"interface":"guest","up":false,"proto":"static","ipv4-address":[{"address":"192.168.90.1","mask":24}]}
        ]});
        let mut local = LocalNetworks::default();
        local.extend_topology(&fw, &interfaces, None).unwrap();
        local.normalize().unwrap();
        assert_eq!(local.ipv4, vec![([192, 168, 80, 0], [255, 255, 255, 0])]);
        assert_eq!(local.ipv6.len(), 1);
    }
    #[test]
    fn deduplicates_prefixes_and_refuses_truncation() {
        let mut local = LocalNetworks::default();
        local.ipv4 = vec![([192, 168, 1, 1], [255, 255, 255, 0]), ([192, 168, 1, 2], [255, 255, 255, 0])];
        local.normalize().unwrap();
        assert_eq!(local.ipv4.len(), 1);
        for i in 0..17 {
            local.ipv4.push(([10, i, 0, 0], [255, 255, 0, 0]));
        }
        assert!(local.normalize().is_err());
    }
    #[test]
    fn renamed_uplink_is_not_local_and_bypass_default_route_is_local() {
        let fw = json!({"values":{
            "a":{".type":"zone","name":"lan","network":["office"]},
            "b":{".type":"zone","name":"internet","network":["uplink"],"input":"REJECT","forward":"REJECT"},
            "f":{".type":"forwarding","src":"lan","dest":"internet"}
        }});
        let runtime = json!({"interface":[
            {"interface":"office","up":true,"proto":"dhcp","route":[{"target":"0.0.0.0","mask":0}],"ipv4-address":[{"address":"192.0.2.1","mask":24}]},
            {"interface":"uplink","up":true,"proto":"dhcp","route":[{"target":"0.0.0.0","mask":0}],"ipv4-address":[{"address":"198.51.100.2","mask":24}]}
        ]});
        let mut local = LocalNetworks::default();
        local.extend_topology(&fw, &runtime, Some(&json!({"values":{}}))).unwrap();
        local.normalize().unwrap();
        assert_eq!(local.ipv4.len(), 1);
        assert_eq!(local.ipv4[0].0, [192, 0, 2, 0]);
        let mut protected = LocalNetworks::default();
        protected
            .extend_topology(
                &fw,
                &runtime,
                Some(&json!({"values":{"dhcp_guest":{".type":"dhcp","interface":"uplink"}}})),
            )
            .unwrap();
        protected.normalize().unwrap();
        assert_eq!(protected.ipv4.len(), 2);
    }
}
