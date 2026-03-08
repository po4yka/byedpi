use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::platform;
use crate::runtime_policy::{
    extract_host, select_initial_group, select_next_group, supports_trigger, ConnectionRoute,
    RuntimeCache,
};
use ciadpi_config::{
    DesyncGroup, DesyncMode, RuntimeConfig, DETECT_CONNECT, DETECT_HTTP_LOCAT, DETECT_TLS_ERR,
    DETECT_TORST,
};
use ciadpi_desync::{build_fake_packet, plan_tcp, plan_udp, DesyncAction, DesyncPlan};
use ciadpi_session::{
    encode_http_connect_reply, encode_socks4_reply, encode_socks5_reply,
    parse_http_connect_request, parse_socks4_request, parse_socks5_request, ClientRequest,
    SessionConfig, SessionError, SessionState, SocketType, TriggerEvent, detect_response_trigger,
    S_ATP_I4, S_ATP_I6, S_AUTH_BAD, S_AUTH_NONE, S_CMD_CONN, S_ER_CMD, S_ER_CONN, S_ER_GEN,
    S_VER5,
};
use mio::net::TcpListener as MioTcpListener;
use mio::{Events, Interest, Poll, Token};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};

const LISTENER: Token = Token(0);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const DESYNC_SEED_BASE: u32 = 7;

#[derive(Clone)]
struct RuntimeState {
    config: Arc<RuntimeConfig>,
    cache: Arc<Mutex<RuntimeCache>>,
}

pub fn run_proxy(config: RuntimeConfig) -> io::Result<()> {
    let mut config = config;
    if config.default_ttl == 0 {
        config.default_ttl = platform::detect_default_ttl()?;
    }
    let cache = RuntimeCache::load(&config);
    let state = RuntimeState {
        config: Arc::new(config),
        cache: Arc::new(Mutex::new(cache)),
    };
    let mut listener = build_listener(&state.config)?;
    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut listener, LISTENER, Interest::READABLE)?;
    let mut events = Events::with_capacity(32);

    loop {
        poll.poll(&mut events, None)?;
        for event in &events {
            if event.token() != LISTENER {
                continue;
            }
            loop {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let state = state.clone();
                        let client = mio_to_std_stream(stream);
                        client.set_nonblocking(false)?;
                        thread::spawn(move || {
                            if let Err(err) = handle_client(client, &state) {
                                eprintln!("ciadpi-rs: client error: {err}");
                            }
                        });
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) => return Err(err),
                }
            }
        }
    }
}

fn build_listener(config: &RuntimeConfig) -> io::Result<MioTcpListener> {
    let listen_addr = SocketAddr::new(config.listen.listen_ip, config.listen.listen_port);
    let domain = match listen_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(listen_addr))?;
    socket.listen(1024)?;
    let listener: TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    Ok(MioTcpListener::from_std(listener))
}

fn handle_client(mut client: TcpStream, state: &RuntimeState) -> io::Result<()> {
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    client.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    if state.config.http_connect {
        return handle_http_connect(client, state);
    }

    let mut first = [0u8; 1];
    client.read_exact(&mut first)?;
    match first[0] {
        0x04 => handle_socks4(client, state, first[0]),
        0x05 => handle_socks5(client, state, first[0]),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported proxy protocol",
        )),
    }
}

fn handle_socks4(mut client: TcpStream, state: &RuntimeState, version: u8) -> io::Result<()> {
    let request = read_socks4_request(&mut client, version)?;
    let session = SessionConfig {
        resolve: state.config.resolve,
        ipv6: state.config.ipv6,
    };
    let resolver = |host: &str, socket_type: SocketType| resolve_name(host, socket_type, &state.config);
    let parsed = parse_socks4_request(&request, session, &resolver);
    match parsed {
        Ok(ClientRequest::Socks4Connect(target)) => {
            let (upstream, route) = connect_target(target.addr, state)?;
            client.write_all(encode_socks4_reply(true).as_bytes())?;
            relay(client, upstream, state, target.addr, route)
        }
        Ok(_) => {
            client.write_all(encode_socks4_reply(false).as_bytes())?;
            Ok(())
        }
        Err(_) => {
            client.write_all(encode_socks4_reply(false).as_bytes())?;
            Ok(())
        }
    }
}

fn handle_socks5(mut client: TcpStream, state: &RuntimeState, version: u8) -> io::Result<()> {
    if version != S_VER5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid socks version"));
    }
    negotiate_socks5(&mut client)?;
    let request = read_socks5_request(&mut client)?;
    let session = SessionConfig {
        resolve: state.config.resolve,
        ipv6: state.config.ipv6,
    };
    let resolver = |host: &str, socket_type: SocketType| resolve_name(host, socket_type, &state.config);

    match parse_socks5_request(&request, SocketType::Stream, session, &resolver) {
        Ok(ClientRequest::Socks5Connect(target)) => {
            match connect_target(target.addr, state) {
                Ok((upstream, route)) => {
                    let reply_addr = upstream
                        .local_addr()
                        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
                    client.write_all(encode_socks5_reply(0, reply_addr).as_bytes())?;
                    relay(client, upstream, state, target.addr, route)
                }
                Err(_) => {
                    let fail = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                    client.write_all(encode_socks5_reply(S_ER_CONN, fail).as_bytes())?;
                    Ok(())
                }
            }
        }
        Ok(ClientRequest::Socks5UdpAssociate(_target)) => {
            if !state.config.udp {
                let fail = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                client.write_all(encode_socks5_reply(S_ER_CMD, fail).as_bytes())?;
                return Ok(());
            }
            handle_socks5_udp_associate(client, state)
        }
        Ok(_) => {
            let fail = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            client.write_all(encode_socks5_reply(S_ER_GEN, fail).as_bytes())?;
            Ok(())
        }
        Err(SessionError { code }) => {
            let fail = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            client.write_all(encode_socks5_reply(code, fail).as_bytes())?;
            Ok(())
        }
    }
}

fn handle_http_connect(mut client: TcpStream, state: &RuntimeState) -> io::Result<()> {
    let request = read_http_connect_request(&mut client)?;
    let resolver = |host: &str, socket_type: SocketType| resolve_name(host, socket_type, &state.config);
    match parse_http_connect_request(&request, &resolver) {
        Ok(ClientRequest::HttpConnect(target)) => match connect_target(target.addr, state) {
            Ok((upstream, route)) => {
                client.write_all(encode_http_connect_reply(true).as_bytes())?;
                relay(client, upstream, state, target.addr, route)
            }
            Err(_) => {
                client.write_all(encode_http_connect_reply(false).as_bytes())?;
                Ok(())
            }
        },
        _ => {
            client.write_all(encode_http_connect_reply(false).as_bytes())?;
            Ok(())
        }
    }
}

fn handle_socks5_udp_associate(mut client: TcpStream, state: &RuntimeState) -> io::Result<()> {
    let relay = build_udp_relay_socket(client.local_addr()?.ip())?;
    let reply_addr = relay.local_addr()?;
    client.write_all(encode_socks5_reply(0, reply_addr).as_bytes())?;

    let running = Arc::new(AtomicBool::new(true));
    let worker_socket = relay.try_clone()?;
    let worker_running = running.clone();
    let config = state.config.clone();
    let group = state.config.groups[state.config.actionable_group()].clone();
    let worker = thread::spawn(move || udp_associate_loop(worker_socket, config, group, worker_running));

    client.set_read_timeout(Some(Duration::from_millis(250)))?;
    let mut buffer = [0u8; 64];
    loop {
        match client.read(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
        if !running.load(Ordering::Relaxed) {
            break;
        }
    }

    running.store(false, Ordering::Relaxed);
    worker
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "udp relay thread panicked"))?
}

fn negotiate_socks5(client: &mut TcpStream) -> io::Result<()> {
    let mut count = [0u8; 1];
    client.read_exact(&mut count)?;
    let mut methods = vec![0u8; count[0] as usize];
    client.read_exact(&mut methods)?;
    let method = if methods.contains(&S_AUTH_NONE) {
        S_AUTH_NONE
    } else {
        S_AUTH_BAD
    };
    client.write_all(&[S_VER5, method])?;
    if method == S_AUTH_BAD {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no supported socks auth method",
        ));
    }
    Ok(())
}

fn read_socks5_request(client: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    client.read_exact(&mut header)?;
    let mut out = header.to_vec();
    match header[3] {
        S_ATP_I4 => {
            let mut tail = [0u8; 6];
            client.read_exact(&mut tail)?;
            out.extend_from_slice(&tail);
        }
        S_ATP_I6 => {
            let mut tail = [0u8; 18];
            client.read_exact(&mut tail)?;
            out.extend_from_slice(&tail);
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            out.extend_from_slice(&len);
            let mut tail = vec![0u8; len[0] as usize + 2];
            client.read_exact(&mut tail)?;
            out.extend_from_slice(&tail);
        }
        _ => {}
    }
    Ok(out)
}

fn read_socks4_request(client: &mut TcpStream, version: u8) -> io::Result<Vec<u8>> {
    let mut out = vec![version];
    let mut fixed = [0u8; 7];
    client.read_exact(&mut fixed)?;
    out.extend_from_slice(&fixed);

    read_until_nul(client, &mut out)?;
    let is_domain = out[4] == 0 && out[5] == 0 && out[6] == 0 && out[7] != 0;
    if is_domain {
        read_until_nul(client, &mut out)?;
    }
    Ok(out)
}

fn read_until_nul(client: &mut TcpStream, out: &mut Vec<u8>) -> io::Result<()> {
    loop {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte)?;
        out.push(byte[0]);
        if byte[0] == 0 {
            return Ok(());
        }
        if out.len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
    }
}

fn read_http_connect_request(client: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = client.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof during http connect request",
            ));
        }
        out.extend_from_slice(&chunk[..n]);
        if out.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(out);
        }
        if out.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http connect request too large",
            ));
        }
    }
}

fn resolve_name(host: &str, _socket_type: SocketType, config: &RuntimeConfig) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 0));
    }
    if !config.resolve {
        return None;
    }
    (host, 0)
        .to_socket_addrs()
        .ok()?
        .find(|addr| config.ipv6 || addr.is_ipv4())
}

fn connect_target(target: SocketAddr, state: &RuntimeState) -> io::Result<(TcpStream, ConnectionRoute)> {
    let mut route = {
        let mut cache = state
            .cache
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "cache mutex poisoned"))?;
        select_initial_group(&state.config, &mut cache, target, None)
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "no matching desync group"))?
    };

    loop {
        match connect_target_via_group(target, state, route.group_index) {
            Ok(stream) => return Ok((stream, route)),
            Err(err) => {
                let Some(next) = select_next_group(
                    &state.config,
                    &route,
                    target,
                    None,
                    DETECT_CONNECT,
                    true,
                ) else {
                    return Err(err);
                };
                {
                    let mut cache = state
                        .cache
                        .lock()
                        .map_err(|_| io::Error::new(io::ErrorKind::Other, "cache mutex poisoned"))?;
                    cache.store(&state.config, target, next.group_index, None)?;
                }
                route = next;
            }
        }
    }
}

fn connect_target_via_group(
    target: SocketAddr,
    state: &RuntimeState,
    group_index: usize,
) -> io::Result<TcpStream> {
    let group = state
        .config
        .groups
        .get(group_index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing desync group"))?;
    let stream = if let Some(upstream) = group.ext_socks {
        connect_via_socks(target, upstream.addr, state.config.listen.bind_ip)
    } else {
        connect_socket(target, state.config.listen.bind_ip)
    }?;

    if group.drop_sack {
        platform::attach_drop_sack(&stream)?;
    }
    Ok(stream)
}

fn connect_via_socks(target: SocketAddr, upstream: SocketAddr, bind_ip: IpAddr) -> io::Result<TcpStream> {
    let mut stream = connect_socket(upstream, bind_ip)?;
    stream.write_all(&[S_VER5, 1, S_AUTH_NONE])?;
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth)?;
    if auth != [S_VER5, S_AUTH_NONE] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upstream socks auth failed",
        ));
    }

    let request = encode_upstream_socks_connect(target);
    stream.write_all(&request)?;
    let reply = read_upstream_socks_reply(&mut stream)?;
    if reply.get(1).copied().unwrap_or(S_ER_GEN) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "upstream socks connect failed",
        ));
    }
    Ok(stream)
}

fn encode_upstream_socks_connect(target: SocketAddr) -> Vec<u8> {
    let mut out = vec![S_VER5, S_CMD_CONN, 0];
    match target {
        SocketAddr::V4(addr) => {
            out.push(S_ATP_I4);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            out.push(S_ATP_I6);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    out
}

fn read_upstream_socks_reply(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let mut out = header.to_vec();
    match header[3] {
        S_ATP_I4 => {
            let mut tail = [0u8; 6];
            stream.read_exact(&mut tail)?;
            out.extend_from_slice(&tail);
        }
        S_ATP_I6 => {
            let mut tail = [0u8; 18];
            stream.read_exact(&mut tail)?;
            out.extend_from_slice(&tail);
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            out.extend_from_slice(&len);
            let mut tail = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut tail)?;
            out.extend_from_slice(&tail);
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid upstream socks reply")),
    }
    Ok(out)
}

fn build_udp_relay_socket(ip: IpAddr) -> io::Result<UdpSocket> {
    let bind_addr = SocketAddr::new(ip, 0);
    let domain = match bind_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(bind_addr))?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(socket)
}

fn udp_associate_loop(
    relay: UdpSocket,
    config: Arc<RuntimeConfig>,
    group: DesyncGroup,
    running: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut udp_client_addr = None;
    let mut buffer = [0u8; 65_535];

    while running.load(Ordering::Relaxed) {
        match relay.recv_from(&mut buffer) {
            Ok((n, sender)) => {
                let known_client = udp_client_addr;
                if known_client.is_none() || known_client == Some(sender) {
                    udp_client_addr = Some(sender);
                    let Some((target, payload)) =
                        parse_socks5_udp_packet(&buffer[..n], &config)
                    else {
                        continue;
                    };
                    let actions = plan_udp(&group, payload, config.default_ttl);
                    execute_udp_actions(&relay, target, &actions)?;
                } else if let Some(client_addr) = udp_client_addr {
                    let packet = encode_socks5_udp_packet(sender, &buffer[..n]);
                    relay.send_to(&packet, client_addr)?;
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(())
}

fn parse_socks5_udp_packet<'a>(
    packet: &'a [u8],
    config: &RuntimeConfig,
) -> Option<(SocketAddr, &'a [u8])> {
    if packet.len() < 4 || packet[2] != 0 {
        return None;
    }
    let atyp = packet[3];
    match atyp {
        S_ATP_I4 => {
            if packet.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            Some((SocketAddr::new(IpAddr::V4(ip), port), &packet[10..]))
        }
        S_ATP_I6 => {
            if packet.len() < 22 || !config.ipv6 {
                return None;
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&packet[4..20]);
            let port = u16::from_be_bytes([packet[20], packet[21]]);
            Some((SocketAddr::new(IpAddr::V6(Ipv6Addr::from(raw)), port), &packet[22..]))
        }
        0x03 => {
            let len = *packet.get(4)? as usize;
            let offset = 5 + len;
            if packet.len() < offset + 2 || !config.resolve {
                return None;
            }
            let host = std::str::from_utf8(&packet[5..offset]).ok()?;
            let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let resolved = resolve_name(host, SocketType::Datagram, config)?;
            Some((SocketAddr::new(resolved.ip(), port), &packet[offset + 2..]))
        }
        _ => None,
    }
}

fn encode_socks5_udp_packet(sender: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    match sender {
        SocketAddr::V4(addr) => {
            packet.push(S_ATP_I4);
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            packet.push(S_ATP_I6);
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    packet.extend_from_slice(payload);
    packet
}

fn execute_udp_actions(
    relay: &UdpSocket,
    target: SocketAddr,
    actions: &[DesyncAction],
) -> io::Result<()> {
    for action in actions {
        match action {
            DesyncAction::Write(bytes) => {
                relay.send_to(bytes, target)?;
            }
            DesyncAction::SetTtl(ttl) => {
                set_udp_ttl(relay, target, *ttl)?;
            }
            DesyncAction::RestoreDefaultTtl => {}
            DesyncAction::WriteUrgent { .. }
            | DesyncAction::SetMd5Sig { .. }
            | DesyncAction::AttachDropSack
            | DesyncAction::DetachDropSack
            | DesyncAction::AwaitWritable => {}
        }
    }
    Ok(())
}

fn set_udp_ttl(relay: &UdpSocket, target: SocketAddr, ttl: u8) -> io::Result<()> {
    match target {
        SocketAddr::V4(_) => relay.set_ttl(ttl as u32),
        SocketAddr::V6(_) => Ok(()),
    }
}

fn connect_socket(target: SocketAddr, bind_ip: IpAddr) -> io::Result<TcpStream> {
    let domain = match target {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    bind_socket(&socket, bind_ip, target)?;
    socket.connect(&SockAddr::from(target))?;
    let stream: TcpStream = socket.into();
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn bind_socket(socket: &Socket, bind_ip: IpAddr, target: SocketAddr) -> io::Result<()> {
    if is_unspecified(bind_ip) {
        return Ok(());
    }
    let bind_addr = match (bind_ip, target) {
        (IpAddr::V4(ip), SocketAddr::V4(_)) => SocketAddr::new(IpAddr::V4(ip), 0),
        (IpAddr::V6(ip), SocketAddr::V6(_)) => SocketAddr::new(IpAddr::V6(ip), 0),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bind ip family does not match target family",
            ))
        }
    };
    socket.bind(&SockAddr::from(bind_addr))
}

fn is_unspecified(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_unspecified(),
    }
}

fn relay(
    mut client: TcpStream,
    mut upstream: TcpStream,
    state: &RuntimeState,
    target: SocketAddr,
    mut route: ConnectionRoute,
) -> io::Result<()> {
    let mut session_state = SessionState::default();

    if needs_first_exchange(&state.config) {
        let request_timeout = client.read_timeout()?;
        if let Some(first_request) = read_optional_first_request(&mut client, request_timeout)? {
            let original_request = first_request;
            let host = extract_host(&original_request);

            loop {
                session_state = SessionState::default();
                session_state.observe_outbound(&original_request);
                let group = state.config.groups[route.group_index].clone();
                if let Err(err) =
                    send_with_group(&mut upstream, &state.config, &group, &original_request, 1)
                {
                    if !supports_trigger(&state.config, DETECT_TORST) {
                        return Err(err);
                    }
                    let Some(next) = select_next_group(
                        &state.config,
                        &route,
                        target,
                        Some(&original_request),
                        DETECT_TORST,
                        true,
                    ) else {
                        return Err(err);
                    };
                    {
                        let mut cache = state
                            .cache
                            .lock()
                            .map_err(|_| io::Error::new(io::ErrorKind::Other, "cache mutex poisoned"))?;
                        cache.store(&state.config, target, next.group_index, host.clone())?;
                    }
                    route = next;
                    upstream = reconnect_target(target, state, route.clone(), host.clone())?.0;
                    continue;
                }

                match read_first_response(
                    &mut upstream,
                    &state.config,
                    &original_request,
                    supports_trigger(&state.config, DETECT_TORST),
                )? {
                    FirstResponse::Forward(bytes) => {
                        session_state.observe_inbound(&bytes);
                        client.write_all(&bytes)?;
                        break;
                    }
                    FirstResponse::NoData => break,
                    FirstResponse::Trigger(trigger) => {
                        let Some(next) = select_next_group(
                            &state.config,
                            &route,
                            target,
                            Some(&original_request),
                            trigger_flag(trigger),
                            true,
                        ) else {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                "auto trigger exhausted all candidate groups",
                            ));
                        };
                        {
                            let mut cache = state
                                .cache
                                .lock()
                                .map_err(|_| io::Error::new(io::ErrorKind::Other, "cache mutex poisoned"))?;
                            cache.store(&state.config, target, next.group_index, host.clone())?;
                        }
                        route = next;
                        upstream = reconnect_target(target, state, route.clone(), host.clone())?.0;
                    }
                }
            }
        }
    }

    relay_streams(client, upstream, state, route.group_index, session_state)
}

fn relay_streams(
    client: TcpStream,
    upstream: TcpStream,
    state: &RuntimeState,
    group_index: usize,
    session_seed: SessionState,
) -> io::Result<()> {
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    upstream.set_read_timeout(None)?;
    upstream.set_write_timeout(None)?;

    let client_reader = client.try_clone()?;
    let client_writer = client.try_clone()?;
    let upstream_reader = upstream.try_clone()?;
    let upstream_writer = upstream.try_clone()?;
    let session_state = Arc::new(Mutex::new(session_seed));
    let outbound_session = session_state.clone();
    let inbound_session = session_state.clone();
    let config = state.config.clone();
    let group = state
        .config
        .groups
        .get(group_index)
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing desync group"))?;
    let drop_sack = group.drop_sack;

    let down = thread::spawn(move || copy_inbound_half(upstream_reader, client_writer, inbound_session));
    let up = thread::spawn(move || {
        copy_outbound_half(
            client_reader,
            upstream_writer,
            config,
            group,
            outbound_session,
        )
    });

    let up_result = up
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "upstream thread panicked"))?;
    let down_result = down
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "downstream thread panicked"))?;

    if drop_sack {
        let _ = platform::detach_drop_sack(&upstream);
    }

    up_result?;
    down_result?;
    Ok(())
}

fn needs_first_exchange(config: &RuntimeConfig) -> bool {
    supports_trigger(config, DETECT_HTTP_LOCAT)
        || supports_trigger(config, DETECT_TLS_ERR)
        || supports_trigger(config, DETECT_TORST)
}

fn read_optional_first_request(
    client: &mut TcpStream,
    fallback_timeout: Option<Duration>,
) -> io::Result<Option<Vec<u8>>> {
    client.set_read_timeout(Some(Duration::from_millis(250)))?;
    let mut buffer = vec![0u8; 16_384];
    let result = match client.read(&mut buffer) {
        Ok(0) => Ok(None),
        Ok(n) => {
            buffer.truncate(n);
            Ok(Some(buffer))
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => Ok(None),
        Err(err) => Err(err),
    };
    client.set_read_timeout(fallback_timeout)?;
    result
}

fn read_first_response(
    upstream: &mut TcpStream,
    config: &RuntimeConfig,
    request: &[u8],
    torst_enabled: bool,
) -> io::Result<FirstResponse> {
    let timeout = first_response_timeout(config, request);
    upstream.set_read_timeout(timeout)?;
    let mut buffer = vec![0u8; config.buffer_size.max(16_384)];
    let result = match upstream.read(&mut buffer) {
        Ok(0) => {
            if torst_enabled {
                Ok(FirstResponse::Trigger(TriggerEvent::Torst))
            } else {
                Ok(FirstResponse::NoData)
            }
        }
        Ok(n) => {
            buffer.truncate(n);
            if let Some(trigger) = detect_response_trigger(request, &buffer) {
                Ok(FirstResponse::Trigger(trigger))
            } else {
                Ok(FirstResponse::Forward(buffer))
            }
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            if torst_enabled && config.timeout_ms != 0 {
                Ok(FirstResponse::Trigger(TriggerEvent::Torst))
            } else {
                Ok(FirstResponse::NoData)
            }
        }
        Err(err)
            if torst_enabled
                && matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::InvalidInput
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::HostUnreachable
                ) =>
        {
            Ok(FirstResponse::Trigger(TriggerEvent::Torst))
        }
        Err(err) => Err(err),
    };
    let _ = upstream.set_read_timeout(None);
    result
}

fn first_response_timeout(config: &RuntimeConfig, request: &[u8]) -> Option<Duration> {
    if config.partial_timeout_ms != 0 && ciadpi_packets::is_tls_client_hello(request) {
        Some(Duration::from_millis(config.partial_timeout_ms as u64))
    } else if config.timeout_ms != 0 {
        Some(Duration::from_millis(config.timeout_ms as u64))
    } else if needs_first_exchange(config) {
        Some(Duration::from_millis(250))
    } else {
        None
    }
}

fn reconnect_target(
    target: SocketAddr,
    state: &RuntimeState,
    mut route: ConnectionRoute,
    host: Option<String>,
) -> io::Result<(TcpStream, ConnectionRoute)> {
    loop {
        match connect_target_via_group(target, state, route.group_index) {
            Ok(stream) => return Ok((stream, route)),
            Err(err) => {
                let Some(next) = select_next_group(
                    &state.config,
                    &route,
                    target,
                    None,
                    DETECT_CONNECT,
                    true,
                ) else {
                    return Err(err);
                };
                {
                    let mut cache = state
                        .cache
                        .lock()
                        .map_err(|_| io::Error::new(io::ErrorKind::Other, "cache mutex poisoned"))?;
                    cache.store(&state.config, target, next.group_index, host.clone())?;
                }
                route = next;
            }
        }
    }
}

fn trigger_flag(trigger: TriggerEvent) -> u32 {
    match trigger {
        TriggerEvent::Redirect => DETECT_HTTP_LOCAT,
        TriggerEvent::SslErr => DETECT_TLS_ERR,
        TriggerEvent::Connect => DETECT_CONNECT,
        TriggerEvent::Torst => DETECT_TORST,
    }
}

enum FirstResponse {
    Forward(Vec<u8>),
    Trigger(TriggerEvent),
    NoData,
}

fn copy_inbound_half(
    mut reader: TcpStream,
    mut writer: TcpStream,
    session: Arc<Mutex<SessionState>>,
) -> io::Result<()> {
    let mut buffer = [0u8; 16_384];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if let Ok(mut state) = session.lock() {
            state.observe_inbound(&buffer[..n]);
        }
        writer.write_all(&buffer[..n])?;
    }
    let _ = writer.shutdown(Shutdown::Write);
    let _ = reader.shutdown(Shutdown::Read);
    Ok(())
}

fn copy_outbound_half(
    mut reader: TcpStream,
    mut writer: TcpStream,
    config: Arc<RuntimeConfig>,
    group: DesyncGroup,
    session: Arc<Mutex<SessionState>>,
) -> io::Result<()> {
    let mut buffer = [0u8; 16_384];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let payload = &buffer[..n];
        let round = {
            let mut state = session
                .lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "session mutex poisoned"))?;
            state.observe_outbound(payload);
            state.round_count as i32
        };
        send_with_group(&mut writer, &config, &group, payload, round)?;
    }
    let _ = writer.shutdown(Shutdown::Write);
    let _ = reader.shutdown(Shutdown::Read);
    Ok(())
}

fn send_with_group(
    writer: &mut TcpStream,
    config: &RuntimeConfig,
    group: &DesyncGroup,
    payload: &[u8],
    round: i32,
) -> io::Result<()> {
    if should_desync_tcp(group, round) {
        let seed = DESYNC_SEED_BASE + (round.saturating_sub(1) as u32);
        match plan_tcp(group, payload, seed, config.default_ttl) {
            Ok(plan) if group.parts.iter().any(|part| part.mode == DesyncMode::Fake) => {
                execute_tcp_plan(writer, config, group, &plan, seed)?
            }
            Ok(plan) => execute_tcp_actions(writer, &plan.actions, config.default_ttl)?,
            Err(_) => writer.write_all(payload)?,
        }
    } else {
        writer.write_all(payload)?;
    }
    Ok(())
}

fn should_desync_tcp(group: &DesyncGroup, round: i32) -> bool {
    has_tcp_actions(group) && check_round(group.rounds, round)
}

fn has_tcp_actions(group: &DesyncGroup) -> bool {
    !group.parts.is_empty() || group.mod_http != 0 || !group.tls_records.is_empty() || group.tlsminor.is_some()
}

fn check_round(rounds: [i32; 2], round: i32) -> bool {
    (rounds[1] == 0 && round <= 1) || (round >= rounds[0] && round <= rounds[1])
}

fn execute_tcp_actions(
    writer: &mut TcpStream,
    actions: &[DesyncAction],
    default_ttl: u8,
) -> io::Result<()> {
    for action in actions {
        match action {
            DesyncAction::Write(bytes) => writer.write_all(bytes)?,
            DesyncAction::WriteUrgent { prefix, urgent_byte } => {
                send_out_of_band(writer, prefix, *urgent_byte)?
            }
            DesyncAction::SetTtl(ttl) => set_stream_ttl(writer, *ttl)?,
            DesyncAction::RestoreDefaultTtl => {
                if default_ttl != 0 {
                    set_stream_ttl(writer, default_ttl)?;
                }
            }
            DesyncAction::SetMd5Sig { key_len } => platform::set_tcp_md5sig(writer, *key_len)?,
            DesyncAction::AttachDropSack => {}
            DesyncAction::DetachDropSack => {}
            DesyncAction::AwaitWritable => {}
        }
    }
    Ok(())
}

fn execute_tcp_plan(
    writer: &mut TcpStream,
    config: &RuntimeConfig,
    group: &DesyncGroup,
    plan: &DesyncPlan,
    seed: u32,
) -> io::Result<()> {
    let fake = build_fake_packet(group, &plan.tampered, seed).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "failed to build fake packet for tcp desync",
        )
    })?;

    let mut cursor = 0usize;
    for step in &plan.steps {
        let start = usize::try_from(step.start)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative tcp plan start"))?;
        let end = usize::try_from(step.end)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative tcp plan end"))?;
        if start < cursor || end < start || end > plan.tampered.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid tcp desync step bounds",
            ));
        }
        let chunk = &plan.tampered[start..end];

        match step.mode {
            DesyncMode::None | DesyncMode::Split => writer.write_all(chunk)?,
            DesyncMode::Oob => {
                send_out_of_band(writer, chunk, group.oob_data.unwrap_or(b'a'))?
            }
            DesyncMode::Disorder => {
                set_stream_ttl(writer, 1)?;
                writer.write_all(chunk)?;
                if config.default_ttl != 0 {
                    set_stream_ttl(writer, config.default_ttl)?;
                }
            }
            DesyncMode::Disoob => {
                set_stream_ttl(writer, 1)?;
                send_out_of_band(writer, chunk, group.oob_data.unwrap_or(b'a'))?;
                if config.default_ttl != 0 {
                    set_stream_ttl(writer, config.default_ttl)?;
                }
            }
            DesyncMode::Fake => {
                let span = chunk.len();
                let fake_end = fake.fake_offset.saturating_add(span).min(fake.bytes.len());
                let fake_chunk = &fake.bytes[fake.fake_offset..fake_end];
                if fake_chunk.len() != span {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "fake packet prefix length does not match original split span",
                    ));
                }
                platform::send_fake_tcp(
                    writer,
                    chunk,
                    fake_chunk,
                    group.ttl.unwrap_or(8),
                    group.md5sig,
                    config.default_ttl,
                    config.wait_send,
                    Duration::from_millis(config.await_interval.max(1) as u64),
                )?;
            }
        }
        cursor = end;
    }

    if cursor < plan.tampered.len() {
        writer.write_all(&plan.tampered[cursor..])?;
    }
    Ok(())
}

fn send_out_of_band(writer: &TcpStream, prefix: &[u8], urgent_byte: u8) -> io::Result<()> {
    let mut packet = Vec::with_capacity(prefix.len() + 1);
    packet.extend_from_slice(prefix);
    packet.push(urgent_byte);
    let sent = SockRef::from(writer).send_out_of_band(&packet)?;
    if sent != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial MSG_OOB send",
        ));
    }
    Ok(())
}

fn set_stream_ttl(stream: &TcpStream, ttl: u8) -> io::Result<()> {
    let socket = SockRef::from(stream);
    let ipv4 = socket.set_ttl(ttl as u32);
    let ipv6 = socket.set_unicast_hops_v6(ttl as u32);
    match (ipv4, ipv6) {
        (Ok(()), _) | (_, Ok(())) => Ok(()),
        (Err(err), _) => Err(err),
    }
}

#[cfg(unix)]
fn mio_to_std_stream(stream: mio::net::TcpStream) -> TcpStream {
    use std::os::fd::{FromRawFd, IntoRawFd};

    let fd = stream.into_raw_fd();
    // SAFETY: ownership of the file descriptor is moved out of the mio stream
    // and transferred directly into the std stream without duplication.
    unsafe { TcpStream::from_raw_fd(fd) }
}

#[cfg(windows)]
fn mio_to_std_stream(stream: mio::net::TcpStream) -> TcpStream {
    use std::os::windows::io::{FromRawSocket, IntoRawSocket};

    let socket = stream.into_raw_socket();
    // SAFETY: ownership of the socket is moved out of the mio stream and
    // transferred directly into the std stream without duplication.
    unsafe { TcpStream::from_raw_socket(socket) }
}
