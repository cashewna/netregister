use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// TCP connect scan of an explicit port list. No SYN scanning, no privileges
/// needed beyond the raw socket used for ARP discovery.
pub fn scan(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> Vec<u16> {
    let mut open = Vec::new();
    for &port in ports {
        let addr = SocketAddr::from((ip, port));
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            open.push(port);
        }
    }
    open.sort_unstable();
    open
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn finds_only_the_listening_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let open_port = listener.local_addr().unwrap().port();
        let closed_port = {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let found = scan(
            Ipv4Addr::LOCALHOST,
            &[open_port, closed_port],
            Duration::from_millis(250),
        );
        assert_eq!(found, vec![open_port]);
    }
}
