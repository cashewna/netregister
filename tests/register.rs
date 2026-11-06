use std::net::Ipv4Addr;

use ipnet::IpNet;
use netregister::config::{check_target, Config};
use netregister::db::{Observation, Outcome, Store};
use netregister::discover::parse_arp_reply;

fn observation(observed_at: i64) -> Observation {
    Observation {
        ip: "172.28.77.3".to_string(),
        mac: "02:42:ac:1c:4d:03".to_string(),
        hostname: Some("lab-nas".to_string()),
        owner: Some("IT Lab".to_string()),
        location: Some("Rack A, shelf 2".to_string()),
        ports: vec![8080],
        observed_at,
    }
}

#[test]
fn register_upsert_is_idempotent_and_advances_last_seen() {
    let store = Store::open_in_memory().unwrap();

    let first = store.upsert_host(&observation(1_000)).unwrap();
    assert_eq!(first.outcome, Outcome::Inserted);
    assert_eq!(first.new_ports, 1);

    let after_first = store.list_hosts().unwrap();
    assert_eq!(after_first.len(), 1);
    assert_eq!(after_first[0].first_seen, 1_000);
    assert_eq!(after_first[0].last_seen, 1_000);

    // Same MAC, same IP, a later scan with an extra open port and no metadata
    // (for example because the config entry was removed). The row must be
    // updated in place, not duplicated, and operator metadata must survive.
    let mut second = observation(1_060);
    second.ip = "172.28.77.30".to_string();
    second.hostname = None;
    second.owner = None;
    second.location = None;
    second.ports = vec![8080, 9100];
    let second_result = store.upsert_host(&second).unwrap();
    assert_eq!(second_result.outcome, Outcome::Updated);
    assert_eq!(second_result.new_ports, 1);

    let after_second = store.list_hosts().unwrap();
    assert_eq!(after_second.len(), 1);
    assert_eq!(store.host_count().unwrap(), 1);
    assert_eq!(after_second[0].ip, "172.28.77.30");
    assert_eq!(after_second[0].first_seen, 1_000);
    assert_eq!(after_second[0].last_seen, 1_060);
    assert_eq!(after_second[0].hostname.as_deref(), Some("lab-nas"));
    assert_eq!(after_second[0].owner.as_deref(), Some("IT Lab"));
    assert_eq!(after_second[0].location.as_deref(), Some("Rack A, shelf 2"));
    assert_eq!(after_second[0].ports, vec![8080, 9100]);
}

#[test]
fn repeated_scan_in_the_same_second_keeps_one_row() {
    let store = Store::open_in_memory().unwrap();
    for _ in 0..3 {
        store.upsert_host(&observation(5_000)).unwrap();
    }
    assert_eq!(store.host_count().unwrap(), 1);
    assert_eq!(store.list_hosts().unwrap()[0].first_seen, 5_000);
    assert_eq!(store.list_hosts().unwrap()[0].last_seen, 5_000);
}

#[test]
fn stale_observation_does_not_move_last_seen_backwards() {
    let store = Store::open_in_memory().unwrap();
    store.upsert_host(&observation(2_000)).unwrap();

    let mut stale = observation(1_500);
    stale.ip = "172.28.77.99".to_string();
    stale.ports = vec![22];
    let result = store.upsert_host(&stale).unwrap();
    assert_eq!(result.outcome, Outcome::Unchanged);
    assert_eq!(result.new_ports, 0);

    let rows = store.list_hosts().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].ip, "172.28.77.3");
    assert_eq!(rows[0].last_seen, 2_000);
    assert_eq!(rows[0].ports, vec![8080]);
}

#[test]
fn scan_target_outside_allow_list_is_refused() {
    let config = Config::from_toml(
        r#"
        [database]
        path = ":memory:"

        [scanner]
        interface = "eth0"
        allowed_networks = ["172.28.77.0/28"]
        "#,
    )
    .unwrap();
    let allowed = config.allowed_networks().unwrap();

    let listed = "172.28.77.0/28".parse::<IpNet>().unwrap();
    assert!(check_target(&listed, &allowed).is_ok());

    let unlisted = "192.168.1.0/24".parse::<IpNet>().unwrap();
    let refusal = check_target(&unlisted, &allowed).unwrap_err();
    assert!(refusal.contains("not within the configured allow-list"));

    let widened = "172.28.0.0/16".parse::<IpNet>().unwrap();
    assert!(check_target(&widened, &allowed).is_err());
}

#[test]
fn parses_discovered_host_frames() {
    // Frame captured in the compose lab: 172.28.77.3 replies with MAC
    // 02:42:ac:1c:4d:03 to the scanner at 172.28.77.10.
    let hex =
        "3a27a753814d0242ac1c4d03080600010800060400020242ac1c4d03ac1c4d033a27a753814dac1c4d0a";
    let frame: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();

    let host = parse_arp_reply(&frame).expect("ARP reply should parse");
    assert_eq!(host.ip, Ipv4Addr::new(172, 28, 77, 3));
    assert_eq!(host.mac, "02:42:ac:1c:4d:03");
}
