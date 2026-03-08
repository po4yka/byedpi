use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ciadpi_config::{
    dump_cache_entries, load_cache_entries_from_path, CacheEntry, DesyncGroup, RuntimeConfig,
    DETECT_RECONN,
};
use ciadpi_packets::{
    is_http, is_tls_client_hello, parse_http, parse_tls, IS_HTTP, IS_HTTPS, IS_IPV4, IS_TCP,
    IS_UDP,
};

#[derive(Debug, Clone)]
pub struct ConnectionRoute {
    pub group_index: usize,
    pub attempted_mask: u64,
}

#[derive(Debug, Clone)]
struct CacheRecord {
    entry: CacheEntry,
    group_index: usize,
}

#[derive(Debug, Default)]
pub struct RuntimeCache {
    records: Vec<CacheRecord>,
}

impl RuntimeCache {
    pub fn load(config: &RuntimeConfig) -> Self {
        let mut records = Vec::new();
        for (group_index, group) in config.groups.iter().enumerate() {
            let Some(path) = group.cache_file.as_deref() else {
                continue;
            };
            if path == "-" {
                continue;
            }
            if let Ok(entries) = load_cache_entries_from_path(Path::new(path)) {
                records.extend(entries.into_iter().map(|entry| CacheRecord { entry, group_index }));
            }
        }
        Self { records }
    }

    pub fn lookup(&mut self, config: &RuntimeConfig, dest: SocketAddr) -> Option<ConnectionRoute> {
        let now = now_unix();
        self.records.retain(|record| !is_expired(config, record, now));
        self.records
            .iter()
            .find(|record| cache_matches(&record.entry, dest))
            .map(|record| ConnectionRoute {
                group_index: record.group_index,
                attempted_mask: 0,
            })
    }

    pub fn store(
        &mut self,
        config: &RuntimeConfig,
        dest: SocketAddr,
        group_index: usize,
        host: Option<String>,
    ) -> io::Result<()> {
        let entry = CacheEntry {
            addr: dest.ip(),
            bits: cache_bits(config, dest.ip()),
            port: dest.port(),
            time: now_unix(),
            host,
        };
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|record| record.group_index == group_index && cache_matches(&record.entry, dest))
        {
            existing.entry = entry;
        } else {
            self.records.push(CacheRecord { entry, group_index });
        }
        self.persist_group(config, group_index)
    }

    fn persist_group(&self, config: &RuntimeConfig, group_index: usize) -> io::Result<()> {
        let Some(path) = config.groups[group_index].cache_file.as_deref() else {
            return Ok(());
        };
        if path == "-" {
            return Ok(());
        }
        let entries: Vec<_> = self
            .records
            .iter()
            .filter(|record| record.group_index == group_index)
            .map(|record| record.entry.clone())
            .collect();
        std::fs::write(path, dump_cache_entries(&entries))
    }
}

pub fn select_initial_group(
    config: &RuntimeConfig,
    cache: &mut RuntimeCache,
    dest: SocketAddr,
    payload: Option<&[u8]>,
) -> Option<ConnectionRoute> {
    if let Some(route) = cache.lookup(config, dest) {
        let group = config.groups.get(route.group_index)?;
        if group_matches(group, dest, payload) {
            return Some(route);
        }
    }

    let mut attempted_mask = 0u64;
    for (idx, group) in config.groups.iter().enumerate() {
        if group.detect != 0 {
            continue;
        }
        if group_matches(group, dest, payload) {
            return Some(ConnectionRoute {
                group_index: idx,
                attempted_mask,
            });
        }
        attempted_mask |= group.bit;
    }
    None
}

pub fn select_next_group(
    config: &RuntimeConfig,
    route: &ConnectionRoute,
    dest: SocketAddr,
    payload: Option<&[u8]>,
    trigger: u32,
    can_reconnect: bool,
) -> Option<ConnectionRoute> {
    let mut attempted_mask = route.attempted_mask | config.groups[route.group_index].bit;
    for (idx, group) in config.groups.iter().enumerate() {
        if attempted_mask & group.bit != 0 {
            continue;
        }
        if group.detect != 0 && (group.detect & trigger) == 0 {
            attempted_mask |= group.bit;
            continue;
        }
        if (group.detect & DETECT_RECONN) != 0 && !can_reconnect {
            attempted_mask |= group.bit;
            continue;
        }
        if group_matches(group, dest, payload) {
            return Some(ConnectionRoute {
                group_index: idx,
                attempted_mask,
            });
        }
        attempted_mask |= group.bit;
    }
    None
}

pub fn supports_trigger(config: &RuntimeConfig, trigger: u32) -> bool {
    config.groups
        .iter()
        .any(|group| group.detect != 0 && (group.detect & trigger) != 0)
}

pub fn extract_host(payload: &[u8]) -> Option<String> {
    parse_http(payload)
        .map(|host| String::from_utf8_lossy(host.host).into_owned())
        .or_else(|| parse_tls(payload).map(|host| String::from_utf8_lossy(host).into_owned()))
}

fn group_matches(group: &DesyncGroup, dest: SocketAddr, payload: Option<&[u8]>) -> bool {
    if !matches_l34(group, dest) {
        return false;
    }
    match payload {
        Some(payload) => matches_payload(group, payload),
        None => group.filters.hosts.is_empty() && payload_proto_known(group),
    }
}

fn payload_proto_known(group: &DesyncGroup) -> bool {
    group.proto == 0 || (group.proto & (IS_HTTP | IS_HTTPS)) == 0
}

fn matches_l34(group: &DesyncGroup, dest: SocketAddr) -> bool {
    if (group.proto & IS_UDP) != 0 {
        return false;
    }
    if (group.proto & IS_TCP) != 0 {
        // Every TCP tunnel in the Rust runtime is stream-based.
    }
    if (group.proto & IS_IPV4) != 0 && !dest.is_ipv4() {
        return false;
    }
    if let Some((start, end)) = group.port_filter {
        let port = dest.port();
        if port < start || port > end {
            return false;
        }
    }
    if !group.filters.ipset.is_empty() && !group.filters.ipset_match(dest.ip()) {
        return false;
    }
    true
}

fn matches_payload(group: &DesyncGroup, payload: &[u8]) -> bool {
    if group.proto != 0 {
        let l7 = group.proto & !(IS_TCP | IS_UDP | IS_IPV4);
        if l7 != 0 {
            let http = is_http(payload);
            let tls = is_tls_client_hello(payload);
            if ((l7 & IS_HTTP) != 0 && http) || ((l7 & IS_HTTPS) != 0 && tls) {
                // allowed
            } else {
                return false;
            }
        }
    }
    if group.filters.hosts.is_empty() {
        return true;
    }
    extract_host(payload)
        .as_deref()
        .is_some_and(|host| group.filters.hosts_match(host))
}

fn cache_matches(entry: &CacheEntry, dest: SocketAddr) -> bool {
    if entry.port != dest.port() {
        return false;
    }
    match (entry.addr, dest.ip()) {
        (IpAddr::V4(lhs), IpAddr::V4(rhs)) => prefix_match(&lhs.octets(), &rhs.octets(), entry.bits as u8),
        (IpAddr::V6(lhs), IpAddr::V6(rhs)) => prefix_match(&lhs.octets(), &rhs.octets(), entry.bits as u8),
        _ => false,
    }
}

fn prefix_match(lhs: &[u8], rhs: &[u8], bits: u8) -> bool {
    let full_bytes = (bits / 8) as usize;
    let rem = bits % 8;
    if lhs.get(..full_bytes) != rhs.get(..full_bytes) {
        return false;
    }
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    lhs[full_bytes] & mask == rhs[full_bytes] & mask
}

fn is_expired(config: &RuntimeConfig, record: &CacheRecord, now: i64) -> bool {
    let Some(group) = config.groups.get(record.group_index) else {
        return true;
    };
    let ttl = if group.cache_ttl != 0 {
        group.cache_ttl
    } else {
        config.cache_ttl
    };
    ttl != 0 && now > record.entry.time + ttl
}

fn cache_bits(config: &RuntimeConfig, ip: IpAddr) -> u16 {
    match ip {
        IpAddr::V4(_) if config.cache_prefix != 0 => (32 - config.cache_prefix as u16).max(1),
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
