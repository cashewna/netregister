use std::net::Ipv4Addr;
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::config::normalize_mac;

const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone)]
pub struct Observation {
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub owner: Option<String>,
    pub location: Option<String>,
    pub ports: Vec<u16>,
    pub observed_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Inserted,
    Updated,
    Unchanged,
}

#[derive(Debug)]
pub struct UpsertResult {
    pub id: i64,
    pub outcome: Outcome,
    pub new_ports: usize,
    pub closed_ports: usize,
}

#[derive(Debug)]
struct ExistingRow {
    id: i64,
    ip: String,
    hostname: Option<String>,
    owner: Option<String>,
    location: Option<String>,
    last_seen: i64,
}

#[derive(Debug, Clone)]
pub struct HostRow {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub owner: Option<String>,
    pub location: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub ports: Vec<u16>,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &str) -> Result<Self, String> {
        if path != ":memory:" {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
                }
            }
        }
        let conn = Connection::open(path).map_err(|e| format!("cannot open {path}: {e}"))?;
        migrate(&conn).map_err(|e| format!("cannot migrate database: {e}"))?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        migrate(&conn).map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }

    /// Insert a host or update the existing row for its MAC. `first_seen` is
    /// immutable; `last_seen` advances; operator metadata is only overwritten
    /// when the new observation carries a value for it.
    pub fn upsert_host(&self, obs: &Observation) -> Result<UpsertResult, String> {
        let mac = normalize_mac(&obs.mac);
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| e.to_string())?;

        let existing: Option<ExistingRow> = tx
            .query_row(
                "SELECT id, ip, hostname, owner, location, last_seen FROM hosts WHERE mac = ?1",
                params![mac],
                |row| {
                    Ok(ExistingRow {
                        id: row.get(0)?,
                        ip: row.get(1)?,
                        hostname: row.get(2)?,
                        owner: row.get(3)?,
                        location: row.get(4)?,
                        last_seen: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;

        // Refuse to move an existing row backwards. This can happen when scans
        // overlap or the system clock steps backwards; the newer observation
        // wins.
        if let Some(row) = &existing {
            if row.last_seen > obs.observed_at {
                return Ok(UpsertResult {
                    id: row.id,
                    outcome: Outcome::Unchanged,
                    new_ports: 0,
                    closed_ports: 0,
                });
            }
        }

        tx.execute(
            "INSERT INTO hosts (mac, ip, hostname, owner, location, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(mac) DO UPDATE SET
                 ip = excluded.ip,
                 hostname = COALESCE(excluded.hostname, hosts.hostname),
                 owner = COALESCE(excluded.owner, hosts.owner),
                 location = COALESCE(excluded.location, hosts.location),
                 last_seen = excluded.last_seen",
            params![
                mac,
                obs.ip,
                obs.hostname,
                obs.owner,
                obs.location,
                obs.observed_at
            ],
        )
        .map_err(|e| e.to_string())?;

        let id: i64 = tx
            .query_row("SELECT id FROM hosts WHERE mac = ?1", params![mac], |row| {
                row.get(0)
            })
            .map_err(|e| e.to_string())?;

        let old_ports: Vec<u16> = {
            let mut stmt = tx
                .prepare("SELECT port FROM open_ports WHERE host_id = ?1")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![id], |row| row.get::<_, u16>(0))
                .map_err(|e| e.to_string())?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| e.to_string())?
        };

        let new_ports = obs.ports.iter().filter(|p| !old_ports.contains(p)).count();
        let closed_ports = old_ports.iter().filter(|p| !obs.ports.contains(p)).count();

        for port in &obs.ports {
            tx.execute(
                "INSERT INTO open_ports (host_id, port, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(host_id, port) DO UPDATE SET last_seen = excluded.last_seen",
                params![id, port, obs.observed_at],
            )
            .map_err(|e| e.to_string())?;
        }
        for port in old_ports.iter().filter(|p| !obs.ports.contains(p)) {
            tx.execute(
                "DELETE FROM open_ports WHERE host_id = ?1 AND port = ?2",
                params![id, port],
            )
            .map_err(|e| e.to_string())?;
        }

        tx.commit().map_err(|e| e.to_string())?;

        let changed = match &existing {
            None => true,
            Some(row) => {
                row.ip != obs.ip
                    || obs
                        .hostname
                        .as_ref()
                        .is_some_and(|value| Some(value) != row.hostname.as_ref())
                    || obs
                        .owner
                        .as_ref()
                        .is_some_and(|value| Some(value) != row.owner.as_ref())
                    || obs
                        .location
                        .as_ref()
                        .is_some_and(|value| Some(value) != row.location.as_ref())
                    || obs.observed_at > row.last_seen
                    || new_ports > 0
                    || closed_ports > 0
            }
        };
        let outcome = match existing {
            None => Outcome::Inserted,
            Some(_) if changed => Outcome::Updated,
            Some(_) => Outcome::Unchanged,
        };
        Ok(UpsertResult {
            id,
            outcome,
            new_ports,
            closed_ports,
        })
    }

    pub fn list_hosts(&self) -> Result<Vec<HostRow>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, mac, ip, hostname, owner, location, first_seen, last_seen
                 FROM hosts",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    HostRow {
                        mac: row.get(1)?,
                        ip: row.get(2)?,
                        hostname: row.get(3)?,
                        owner: row.get(4)?,
                        location: row.get(5)?,
                        first_seen: row.get(6)?,
                        last_seen: row.get(7)?,
                        ports: Vec::new(),
                    },
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut hosts: Vec<(i64, HostRow)> = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())?;

        for (id, host) in &mut hosts {
            let mut stmt = self
                .conn
                .prepare("SELECT port FROM open_ports WHERE host_id = ?1 ORDER BY port")
                .map_err(|e| e.to_string())?;
            host.ports = stmt
                .query_map(params![*id], |row| row.get::<_, u16>(0))
                .map_err(|e| e.to_string())?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| e.to_string())?;
        }

        hosts.sort_by_key(|(_, row)| {
            row.ip
                .parse::<Ipv4Addr>()
                .map(u32::from)
                .unwrap_or(u32::MAX)
        });
        Ok(hosts.into_iter().map(|(_, row)| row).collect())
    }

    pub fn host_count(&self) -> Result<i64, String> {
        self.conn
            .query_row("SELECT COUNT(*) FROM hosts", [], |row| row.get(0))
            .map_err(|e| e.to_string())
    }

    pub fn port_count(&self) -> Result<i64, String> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM open_ports p JOIN hosts h ON h.id = p.host_id",
                [],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())
    }
}

fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "foreign_keys", "ON")?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }
    if version < 1 {
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS hosts (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 mac TEXT NOT NULL UNIQUE COLLATE NOCASE,
                 ip TEXT NOT NULL,
                 hostname TEXT,
                 owner TEXT,
                 location TEXT,
                 first_seen INTEGER NOT NULL,
                 last_seen INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
             CREATE TABLE IF NOT EXISTS open_ports (
                 host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                 port INTEGER NOT NULL,
                 first_seen INTEGER NOT NULL,
                 last_seen INTEGER NOT NULL,
                 PRIMARY KEY (host_id, port)
             );
             PRAGMA user_version = 1;
             COMMIT;",
        )?;
    }
    Ok(())
}
