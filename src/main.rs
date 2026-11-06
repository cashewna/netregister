use std::path::PathBuf;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use ipnet::IpNet;

use netregister::config::{check_target, Config};
use netregister::db::Store;
use netregister::register::{self, ScanReport};
use netregister::timefmt::iso8601;

#[derive(Debug, Parser)]
#[command(
    name = "netregister",
    version,
    about = "ARP-based asset register for one local network segment"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(
        long,
        global = true,
        default_value = "netregister.toml",
        env = "NETREGISTER_CONFIG"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover hosts on an allow-listed network segment and upsert the register.
    Scan {
        /// Target network in CIDR notation, e.g. 192.168.1.0/24.
        #[arg(long)]
        network: String,

        /// Explicit opt-in to scan a network that is not in the allow-list.
        #[arg(long)]
        allow_unlisted_network: bool,

        /// Emit the summary as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Print the current inventory.
    List {
        #[arg(long, value_enum, default_value_t = ListFormat::Table)]
        format: ListFormat,
    },

    /// Print inventory counts.
    Stats {
        #[arg(long, value_enum, default_value_t = ListFormat::Table)]
        format: ListFormat,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ListFormat {
    Table,
    Tsv,
    Json,
}

fn main() {
    let cli = Cli::parse();
    if let Err(message) = run(cli) {
        eprintln!("error: {message}");
        exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let config = Config::load(&cli.config).map_err(|e| e.to_string())?;
    match cli.command {
        Command::Scan {
            network,
            allow_unlisted_network,
            json,
        } => {
            let target = network
                .parse::<IpNet>()
                .map_err(|e| format!("invalid --network {network:?}: {e}"))?
                .trunc();
            let allowed = config.allowed_networks().map_err(|e| e.to_string())?;
            if let Err(message) = check_target(&target, &allowed) {
                if allow_unlisted_network {
                    eprintln!(
                        "warning: {message}; continuing because --allow-unlisted-network was passed"
                    );
                } else {
                    eprintln!("refusing to scan: {message}");
                    eprintln!(
                        "hint: add the network to scanner.allowed_networks, or pass --allow-unlisted-network to widen the allow-list for this run"
                    );
                    exit(2);
                }
            }
            let store = Store::open(&config.database.path)?;
            let report = register::scan(
                &store,
                &config,
                &target,
                now_epoch(),
                allow_unlisted_network,
            )?;
            if json {
                println!("{}", report_json(&report));
            } else {
                println!("{}", report.summary());
            }
        }
        Command::List { format } => {
            let store = Store::open(&config.database.path)?;
            let hosts = store.list_hosts()?;
            match format {
                ListFormat::Table => print_table(&hosts),
                ListFormat::Tsv => {
                    for host in &hosts {
                        println!(
                            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                            host.mac,
                            host.ip,
                            host.hostname.as_deref().unwrap_or(""),
                            host.owner.as_deref().unwrap_or(""),
                            host.location.as_deref().unwrap_or(""),
                            host.first_seen,
                            host.last_seen,
                            host.ports
                                .iter()
                                .map(u16::to_string)
                                .collect::<Vec<_>>()
                                .join(",")
                        );
                    }
                }
                ListFormat::Json => {
                    let rows: Vec<_> = hosts
                        .iter()
                        .map(|host| {
                            serde_json::json!({
                                "mac": host.mac,
                                "ip": host.ip,
                                "hostname": host.hostname,
                                "owner": host.owner,
                                "location": host.location,
                                "first_seen": host.first_seen,
                                "first_seen_iso": iso8601(host.first_seen),
                                "last_seen": host.last_seen,
                                "last_seen_iso": iso8601(host.last_seen),
                                "open_ports": host.ports,
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?
                    );
                }
            }
        }
        Command::Stats { format } => {
            let store = Store::open(&config.database.path)?;
            let hosts = store.host_count()?;
            let ports = store.port_count()?;
            match format {
                ListFormat::Table => println!("hosts={hosts} ports={ports}"),
                ListFormat::Tsv => println!("{hosts}\t{ports}"),
                ListFormat::Json => {
                    println!("{}", serde_json::json!({ "hosts": hosts, "ports": ports }))
                }
            }
        }
    }
    Ok(())
}

fn report_json(report: &ScanReport) -> String {
    serde_json::json!({
        "network": report.network,
        "discovered": report.discovered,
        "inserted": report.inserted,
        "updated": report.updated,
        "unchanged": report.unchanged,
        "new_ports": report.new_ports,
        "closed_ports": report.closed_ports,
    })
    .to_string()
}

fn print_table(hosts: &[netregister::db::HostRow]) {
    println!(
        "{:<17}  {:<15}  {:<18}  {:<16}  {:<20}  {:<20}  {:<20}  PORTS",
        "MAC", "IP", "HOSTNAME", "OWNER", "LOCATION", "FIRST SEEN", "LAST SEEN"
    );
    for host in hosts {
        println!(
            "{:<17}  {:<15}  {:<18}  {:<16}  {:<20}  {:<20}  {:<20}  {}",
            host.mac,
            host.ip,
            host.hostname.as_deref().unwrap_or("unknown"),
            host.owner.as_deref().unwrap_or("unassigned"),
            host.location.as_deref().unwrap_or("unknown"),
            iso8601(host.first_seen),
            iso8601(host.last_seen),
            if host.ports.is_empty() {
                "-".to_string()
            } else {
                host.ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            }
        );
    }
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
