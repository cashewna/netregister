use std::fmt;
use std::fs;
use std::path::Path;

use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,
    pub scanner: ScannerConfig,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScannerConfig {
    pub interface: String,
    #[serde(default)]
    pub allowed_networks: Vec<String>,
    #[serde(default = "default_ports")]
    pub ports: Vec<u16>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// Operator-supplied metadata for one device. At least one of `mac` or `ip`
/// must be present. Matching prefers `mac`, because an IP can be reassigned.
#[derive(Debug, Clone, Deserialize)]
pub struct Asset {
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub owner: Option<String>,
    pub location: Option<String>,
}

fn default_ports() -> Vec<u16> {
    vec![22, 80, 443, 8080]
}

fn default_timeout_ms() -> u64 {
    1_000
}

#[derive(Debug)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError(e.to_string())
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        ConfigError(e.to_string())
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("cannot read {}: {e}", path.display())))?;
        let cfg: Config = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_toml(raw: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.database.path.trim().is_empty() {
            return Err(ConfigError("database.path must not be empty".into()));
        }
        if self.scanner.interface.trim().is_empty() {
            return Err(ConfigError("scanner.interface must not be empty".into()));
        }
        for net in &self.scanner.allowed_networks {
            net.parse::<IpNet>()
                .map_err(|e| ConfigError(format!("invalid allowed_networks entry {net:?}: {e}")))?;
        }
        for (i, asset) in self.assets.iter().enumerate() {
            if asset.mac.is_none() && asset.ip.is_none() {
                return Err(ConfigError(format!(
                    "assets[{i}] must set mac, ip, or both"
                )));
            }
            if let Some(mac) = &asset.mac {
                if !is_valid_mac(mac) {
                    return Err(ConfigError(format!(
                        "assets[{i}] has invalid mac {mac:?}; expected six hex octets separated by ':' or '-'"
                    )));
                }
            }
            if let Some(ip) = &asset.ip {
                if ip.parse::<std::net::Ipv4Addr>().is_err() {
                    return Err(ConfigError(format!(
                        "assets[{i}] has invalid IPv4 address {ip:?}"
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn allowed_networks(&self) -> Result<Vec<IpNet>, ConfigError> {
        self.scanner
            .allowed_networks
            .iter()
            .map(|s| {
                s.parse::<IpNet>()
                    .map(|n| n.trunc())
                    .map_err(|e| ConfigError(format!("invalid allowed_networks entry {s:?}: {e}")))
            })
            .collect()
    }

    /// Match by MAC first, then by IP. MAC addresses are compared
    /// case-insensitively and in canonical colon notation.
    pub fn asset_for(&self, ip: &str, mac: &str) -> Option<&Asset> {
        let mac = normalize_mac(mac);
        self.assets
            .iter()
            .find(|a| {
                a.mac
                    .as_deref()
                    .map(normalize_mac)
                    .is_some_and(|m| m == mac)
            })
            .or_else(|| {
                self.assets
                    .iter()
                    .find(|a| a.ip.as_deref().is_some_and(|i| i == ip))
            })
    }
}

pub fn normalize_mac(mac: &str) -> String {
    mac.trim().replace('-', ":").to_ascii_lowercase()
}

fn is_valid_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.trim().split([':', '-']).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok())
}

/// A scan target is permitted only when it is equal to, or contained in, one
/// of the configured allow-list networks. Widening the request (for example
/// asking for a /16 when a /24 is allowed) is refused.
pub fn check_target(target: &IpNet, allowed: &[IpNet]) -> Result<(), String> {
    let target = target.trunc();
    for net in allowed {
        let same_family = matches!(
            (target, net),
            (IpNet::V4(_), IpNet::V4(_)) | (IpNet::V6(_), IpNet::V6(_))
        );
        if same_family && target.prefix_len() >= net.prefix_len() && net.contains(&target.network())
        {
            return Ok(());
        }
    }
    Err(format!(
        "target network {target} is not within the configured allow-list [{}]",
        allowed
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
        [database]
        path = "/tmp/example.db"

        [scanner]
        interface = "eth0"
        allowed_networks = ["172.28.77.0/28"]

        [[assets]]
        mac = "02:42:AC:1C:4D:02"
        hostname = "lab-nas"
        owner = "IT Lab"
        location = "Rack A"
    "#;

    #[test]
    fn loads_config_and_matches_asset_by_canonical_mac() {
        let cfg = Config::from_toml(EXAMPLE).unwrap();
        let asset = cfg
            .asset_for("172.28.77.2", "02-42-ac-1c-4d-02")
            .expect("asset should match a differently formatted MAC");
        assert_eq!(asset.hostname.as_deref(), Some("lab-nas"));
        assert_eq!(asset.owner.as_deref(), Some("IT Lab"));
    }

    #[test]
    fn rejects_asset_without_mac_or_ip() {
        let raw = EXAMPLE.replace("mac = \"02:42:AC:1C:4D:02\"", "");
        assert!(Config::from_toml(&raw).is_err());
    }

    #[test]
    fn rejects_invalid_mac_and_ipv6_asset_address() {
        let bad_mac = EXAMPLE.replace("02:42:AC:1C:4D:02", "02:42:AC:1C:4D");
        assert!(Config::from_toml(&bad_mac).is_err());

        let bad_ip = EXAMPLE.replace("mac = \"02:42:AC:1C:4D:02\"", "ip = \"2001:db8::1\"");
        assert!(Config::from_toml(&bad_ip).is_err());
    }

    #[test]
    fn allow_list_accepts_exact_and_narrower_targets() {
        let allowed = [("172.28.77.0/28").parse::<IpNet>().unwrap()];
        assert!(check_target(&"172.28.77.0/28".parse().unwrap(), &allowed).is_ok());
        assert!(check_target(&"172.28.77.0/29".parse().unwrap(), &allowed).is_ok());
    }

    #[test]
    fn allow_list_refuses_unlisted_and_wider_targets() {
        let allowed = [("172.28.77.0/28").parse::<IpNet>().unwrap()];
        let outside = "10.0.0.0/24".parse().unwrap();
        let wider = "172.28.0.0/16".parse().unwrap();
        assert!(check_target(&outside, &allowed).is_err());
        assert!(check_target(&wider, &allowed).is_err());
        assert!(check_target(&"172.28.77.0/28".parse().unwrap(), &[]).is_err());
    }
}
