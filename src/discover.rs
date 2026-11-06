use std::collections::BTreeMap;
use std::ffi::CString;
use std::mem;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use ipnet::IpNet;

/// A host observed on the local segment from an ARP reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredHost {
    pub ip: Ipv4Addr,
    pub mac: String,
}

/// Parse a complete Ethernet frame carrying an ARP reply. Returns `None` for
/// anything that is not a well-formed IPv4 ARP reply.
pub fn parse_arp_reply(frame: &[u8]) -> Option<DiscoveredHost> {
    if frame.len() < 42 {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != 0x0806 {
        return None;
    }
    let htype = u16::from_be_bytes([frame[14], frame[15]]);
    let ptype = u16::from_be_bytes([frame[16], frame[17]]);
    let hlen = frame[18];
    let plen = frame[19];
    let op = u16::from_be_bytes([frame[20], frame[21]]);
    if htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4 || op != 2 {
        return None;
    }
    let mac = format_mac(&frame[22..28]);
    let ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    if ip.is_unspecified() {
        return None;
    }
    Some(DiscoveredHost { ip, mac })
}

pub fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Sniff the local segment with ARP requests and collect the replies.
///
/// This requires `CAP_NET_RAW` (or root) and only works for hosts on the same
/// L2 segment as `interface`.
pub fn scan(
    interface: &str,
    network: &IpNet,
    timeout: Duration,
) -> Result<Vec<DiscoveredHost>, String> {
    let targets = host_addresses(network)?;
    let (source_ip, source_mac, ifindex) = interface_info(interface)?;
    let socket = ArpSocket::open(interface, ifindex)?;

    for target in &targets {
        let frame = build_request(source_mac, source_ip, *target);
        socket.send(&frame)?;
    }

    let deadline = Instant::now() + timeout;
    let mut seen: BTreeMap<Ipv4Addr, DiscoveredHost> = BTreeMap::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline && seen.len() < targets.len() {
        match socket.receive(&mut buf) {
            Ok(n) => {
                if let Some(host) = parse_arp_reply(&buf[..n]) {
                    if host.ip != source_ip && targets.contains(&host.ip) {
                        seen.insert(host.ip, host);
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(format!("ARP receive failed: {error}")),
        }
    }
    Ok(seen.into_values().collect())
}

/// Enumerate usable host addresses in a target network. Refuses networks with
/// more than 4096 hosts so an accidental large prefix cannot become a sweep.
pub fn host_addresses(network: &IpNet) -> Result<Vec<Ipv4Addr>, String> {
    let net = match network {
        IpNet::V4(net) => net,
        IpNet::V6(_) => return Err("only IPv4 segments are supported".into()),
    };
    let prefix = net.prefix_len();
    if !(16..=30).contains(&prefix) {
        return Err(format!(
            "target prefix /{prefix} is outside the supported range /16../30"
        ));
    }
    let base = u32::from(net.network());
    let mask = u32::MAX << (32 - u32::from(prefix));
    let broadcast = base | !mask;
    let count = u64::from(broadcast.saturating_sub(base).saturating_sub(1));
    if count > 4096 {
        return Err(format!(
            "target network has {count} addresses; the limit is 4096"
        ));
    }
    Ok((base + 1..broadcast).map(Ipv4Addr::from).collect())
}

fn build_request(source_mac: [u8; 6], source_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&source_mac);
    frame.extend_from_slice(&0x0806u16.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.push(6);
    frame.push(4);
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&source_mac);
    frame.extend_from_slice(&source_ip.octets());
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&target_ip.octets());
    frame
}

struct ArpSocket {
    fd: libc::c_int,
    ifindex: i32,
}

impl ArpSocket {
    fn open(interface: &str, ifindex: i32) -> Result<Self, String> {
        let protocol = (libc::ETH_P_ARP as u16).to_be() as libc::c_int;
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) };
        if fd < 0 {
            return Err(format!(
                "cannot open raw ARP socket on {interface}: {}. Discovery needs CAP_NET_RAW (run as root or add the capability).",
                std::io::Error::last_os_error()
            ));
        }
        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
        addr.sll_ifindex = ifindex;
        let bound = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if bound < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!("cannot bind ARP socket to {interface}: {err}"));
        }
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!("cannot set ARP socket receive timeout: {err}"));
        }
        Ok(Self { fd, ifindex })
    }

    fn send(&self, frame: &[u8]) -> Result<(), String> {
        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
        addr.sll_ifindex = self.ifindex;
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);
        let sent = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if sent < 0 || sent as usize != frame.len() {
            return Err(format!(
                "failed to send ARP request: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn receive(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

impl Drop for ArpSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn interface_info(interface: &str) -> Result<(Ipv4Addr, [u8; 6], i32), String> {
    let name = CString::new(interface).map_err(|_| "interface name contains NUL".to_string())?;
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if ifindex == 0 {
        return Err(format!("unknown network interface {interface:?}"));
    }
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(format!(
            "cannot open interface socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = name.as_bytes();
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name_bytes) {
        *dst = *src as libc::c_char;
    }

    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFADDR as _, &mut ifr) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!(
            "interface {interface:?} has no IPv4 address: {err}"
        ));
    }
    let source_ip = unsafe {
        let sa = &ifr.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in;
        Ipv4Addr::from(u32::from_be((*sa).sin_addr.s_addr))
    };

    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as _, &mut ifr) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("cannot read MAC of {interface:?}: {err}"));
    }
    let mut source_mac = [0u8; 6];
    unsafe {
        for (i, slot) in source_mac.iter_mut().enumerate() {
            *slot = ifr.ifr_ifru.ifru_hwaddr.sa_data[i] as u8;
        }
    }
    unsafe { libc::close(fd) };
    Ok((source_ip, source_mac, ifindex as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured Ethernet+ARP reply shape: host 172.28.77.3 answering the
    // scanner at 172.28.77.10.
    const REPLY_HEX: &str =
        "3a27a753814d0242ac1c4d03080600010800060400020242ac1c4d03ac1c4d033a27a753814dac1c4d0a";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn parses_labelled_arp_reply_from_fixture() {
        let frame = hex_to_bytes(REPLY_HEX);
        let host = parse_arp_reply(&frame).expect("valid ARP reply");
        assert_eq!(host.ip, "172.28.77.3".parse::<Ipv4Addr>().unwrap());
        assert_eq!(host.mac, "02:42:ac:1c:4d:03");
    }

    #[test]
    fn ignores_arp_requests_and_truncated_frames() {
        let mut request = hex_to_bytes(REPLY_HEX);
        request[21] = 1; // op = request
        assert_eq!(parse_arp_reply(&request), None);
        assert_eq!(parse_arp_reply(&hex_to_bytes(REPLY_HEX)[..30]), None);
        assert_eq!(parse_arp_reply(&[]), None);
    }

    #[test]
    fn enumerates_usable_hosts_for_a_slash_28() {
        let hosts = host_addresses(&"172.28.77.0/28".parse().unwrap()).unwrap();
        assert_eq!(hosts.len(), 14);
        assert_eq!(hosts.first(), Some(&"172.28.77.1".parse().unwrap()));
        assert_eq!(hosts.last(), Some(&"172.28.77.14".parse().unwrap()));
    }

    #[test]
    fn refuses_oversized_segments() {
        assert!(host_addresses(&"10.0.0.0/8".parse().unwrap()).is_err());
        assert!(host_addresses(&"10.0.0.0/31".parse().unwrap()).is_err());
    }
}
