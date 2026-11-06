use std::time::Duration;

use ipnet::IpNet;

use crate::config::{check_target, Config};
use crate::db::{Observation, Outcome, Store};
use crate::{discover, ports};

#[derive(Debug, Default)]
pub struct ScanReport {
    pub network: String,
    pub discovered: usize,
    pub inserted: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub new_ports: usize,
    pub closed_ports: usize,
}

impl ScanReport {
    pub fn summary(&self) -> String {
        format!(
            "scan network={} discovered={} inserted={} updated={} unchanged={} new_ports={} closed_ports={}",
            self.network,
            self.discovered,
            self.inserted,
            self.updated,
            self.unchanged,
            self.new_ports,
            self.closed_ports
        )
    }
}

/// Discover hosts on `network`, probe the configured ports, and persist the
/// result. Discovery only sends ARP requests inside `network`.
pub fn scan(
    store: &Store,
    config: &Config,
    network: &IpNet,
    observed_at: i64,
    allow_unlisted: bool,
) -> Result<ScanReport, String> {
    // Defence in depth: the CLI checks this too so it can exit with a policy
    // code, but the library must never sweep an unlisted network by itself.
    if !allow_unlisted {
        let allowed = config.allowed_networks().map_err(|e| e.to_string())?;
        check_target(network, &allowed)?;
    }
    let timeout = Duration::from_millis(config.scanner.timeout_ms);
    let discovered = discover::scan(&config.scanner.interface, network, timeout)?;
    let port_timeout = std::cmp::min(timeout, Duration::from_millis(300));

    let mut report = ScanReport {
        network: network.to_string(),
        discovered: discovered.len(),
        ..ScanReport::default()
    };

    for host in &discovered {
        let ip = host.ip.to_string();
        let asset = config.asset_for(&ip, &host.mac);
        let open_ports = ports::scan(host.ip, &config.scanner.ports, port_timeout);
        let observation = Observation {
            ip,
            mac: host.mac.clone(),
            hostname: asset.and_then(|a| a.hostname.clone()),
            owner: asset.and_then(|a| a.owner.clone()),
            location: asset.and_then(|a| a.location.clone()),
            ports: open_ports,
            observed_at,
        };
        let result = store.upsert_host(&observation)?;
        match result.outcome {
            Outcome::Inserted => report.inserted += 1,
            Outcome::Updated => report.updated += 1,
            Outcome::Unchanged => report.unchanged += 1,
        }
        report.new_ports += result.new_ports;
        report.closed_ports += result.closed_ports;
    }

    Ok(report)
}
