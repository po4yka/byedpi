use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;

use ciadpi_session::{
    detect_response_trigger, encode_http_connect_reply, encode_socks4_reply, encode_socks5_reply,
    parse_http_connect_request, parse_socks4_request, parse_socks5_request, ClientRequest,
    SessionConfig, SocketType, TriggerEvent, S_ER_OK,
};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn oracle_bin() -> PathBuf {
    repo_root().join("tests").join("bin").join("oracle_protocol")
}

fn packet_corpus(name: &str) -> PathBuf {
    repo_root().join("tests").join("corpus").join("packets").join(name)
}

fn run_oracle(args: &[&str]) -> Value {
    let oracle = oracle_bin();
    assert!(
        oracle.exists(),
        "missing protocol oracle at {}. Run `make oracles` first.",
        oracle.display()
    );
    let output = Command::new(&oracle)
        .args(args)
        .output()
        .expect("oracle invocation");
    assert!(
        output.status.success(),
        "oracle failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("oracle json")
}

fn write_temp(bytes: &[u8], name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ciadpi-session-{name}-{}.bin", std::process::id()));
    fs::write(&path, bytes).expect("write temp");
    path
}

fn resolver(host: &str, _: SocketType) -> Option<SocketAddr> {
    match host {
        "localhost" => Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        _ => None,
    }
}

fn assert_target(request: &ClientRequest, expected_port: u64, expected_family: &str) {
    let target = match request {
        ClientRequest::Socks4Connect(target)
        | ClientRequest::Socks5Connect(target)
        | ClientRequest::Socks5UdpAssociate(target)
        | ClientRequest::HttpConnect(target) => target,
    };
    assert_eq!(target.addr.port() as u64, expected_port);
    assert_eq!(target.family(), expected_family);
}

#[test]
fn socks4_request_matches_oracle() {
    let payload = [&[0x04, 0x01][..], &(8080u16.to_be_bytes()), &Ipv4Addr::LOCALHOST.octets(), b"user\0"].concat();
    let path = write_temp(&payload, "socks4");
    let oracle = run_oracle(&["socks4", path.to_str().unwrap()]);
    let rust = parse_socks4_request(&payload, SessionConfig::default(), &resolver).expect("socks4 parse");

    assert!(oracle["ok"].as_bool().unwrap());
    assert_target(&rust, oracle["addr"]["port"].as_u64().unwrap(), oracle["addr"]["family"].as_str().unwrap());
    let _ = fs::remove_file(path);
}

#[test]
fn socks4a_request_matches_oracle() {
    let payload = [&[0x04, 0x01][..], &(8081u16.to_be_bytes()), &[0, 0, 0, 1], b"user\0localhost\0"].concat();
    let path = write_temp(&payload, "socks4a");
    let oracle = run_oracle(&["socks4", path.to_str().unwrap()]);
    let rust = parse_socks4_request(&payload, SessionConfig::default(), &resolver).expect("socks4a parse");

    assert!(oracle["ok"].as_bool().unwrap());
    assert_target(&rust, oracle["addr"]["port"].as_u64().unwrap(), "ipv4");
    let _ = fs::remove_file(path);
}

#[test]
fn socks5_connect_and_udp_match_oracle() {
    let connect = [&[0x05, 0x01, 0x00, 0x01][..], &Ipv4Addr::LOCALHOST.octets(), &(443u16.to_be_bytes())].concat();
    let dgram = [&[0x05, 0x03, 0x00, 0x01][..], &Ipv4Addr::LOCALHOST.octets(), &(5353u16.to_be_bytes())].concat();
    let connect_path = write_temp(&connect, "socks5-connect");
    let dgram_path = write_temp(&dgram, "socks5-dgram");

    let connect_oracle = run_oracle(&["socks5", connect_path.to_str().unwrap()]);
    let dgram_oracle = run_oracle(&["socks5", dgram_path.to_str().unwrap(), "dgram"]);
    let connect_rust = parse_socks5_request(&connect, SocketType::Stream, SessionConfig::default(), &resolver)
        .expect("socks5 connect");
    let dgram_rust = parse_socks5_request(&dgram, SocketType::Datagram, SessionConfig::default(), &resolver)
        .expect("socks5 udp");

    assert_target(
        &connect_rust,
        connect_oracle["addr"]["port"].as_u64().unwrap(),
        connect_oracle["addr"]["family"].as_str().unwrap(),
    );
    assert_target(
        &dgram_rust,
        dgram_oracle["addr"]["port"].as_u64().unwrap(),
        dgram_oracle["addr"]["family"].as_str().unwrap(),
    );
    let _ = fs::remove_file(connect_path);
    let _ = fs::remove_file(dgram_path);
}

#[test]
fn socks5_domain_and_ipv6_match_oracle() {
    let domain = b"localhost";
    let domain_payload = [&[0x05, 0x01, 0x00, 0x03, domain.len() as u8][..], domain, &(443u16.to_be_bytes())].concat();
    let mut ipv6_payload = vec![0x05, 0x01, 0x00, 0x04];
    ipv6_payload.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    ipv6_payload.extend_from_slice(&9443u16.to_be_bytes());

    let domain_path = write_temp(&domain_payload, "socks5-domain");
    let ipv6_path = write_temp(&ipv6_payload, "socks5-ipv6");
    let domain_oracle = run_oracle(&["socks5", domain_path.to_str().unwrap()]);
    let ipv6_oracle = run_oracle(&["socks5", ipv6_path.to_str().unwrap()]);
    let domain_rust = parse_socks5_request(&domain_payload, SocketType::Stream, SessionConfig::default(), &resolver)
        .expect("domain request");
    let ipv6_rust = parse_socks5_request(&ipv6_payload, SocketType::Stream, SessionConfig::default(), &resolver)
        .expect("ipv6 request");

    assert_target(&domain_rust, domain_oracle["addr"]["port"].as_u64().unwrap(), "ipv4");
    assert_target(
        &ipv6_rust,
        ipv6_oracle["addr"]["port"].as_u64().unwrap(),
        ipv6_oracle["addr"]["family"].as_str().unwrap(),
    );
    let _ = fs::remove_file(domain_path);
    let _ = fs::remove_file(ipv6_path);
}

#[test]
fn http_connect_matches_oracle() {
    let payload = b"CONNECT 127.0.0.1:8443 HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n".to_vec();
    let path = write_temp(&payload, "http-connect");
    let oracle = run_oracle(&["http_connect", path.to_str().unwrap()]);
    let rust = parse_http_connect_request(&payload, &|host: &str, _| {
        Some(SocketAddr::new(host.parse::<IpAddr>().unwrap(), 0))
    })
    .expect("http connect");

    assert_target(&rust, oracle["addr"]["port"].as_u64().unwrap(), oracle["addr"]["family"].as_str().unwrap());
    let _ = fs::remove_file(path);
}

#[test]
fn invalid_socks5_request_matches_oracle_failure() {
    let payload = vec![0x05, 0x01, 0x00];
    let path = write_temp(&payload, "socks5-invalid");
    let oracle = run_oracle(&["socks5", path.to_str().unwrap()]);
    let rust = parse_socks5_request(&payload, SocketType::Stream, SessionConfig::default(), &resolver);

    assert!(!oracle["ok"].as_bool().unwrap());
    assert!(rust.is_err());
    let _ = fs::remove_file(path);
}

#[test]
fn reply_encoding_matches_c_contract() {
    let socks4 = encode_socks4_reply(true);
    assert_eq!(socks4.as_bytes(), &[0, 0x5a, 0, 0, 0, 0, 0, 0]);

    let socks5 = encode_socks5_reply(
        S_ER_OK,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080),
    );
    assert_eq!(
        socks5.as_bytes(),
        &[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]
    );

    let http = encode_http_connect_reply(true);
    assert_eq!(http.as_bytes(), b"HTTP/1.1 200 OK\r\n\r\n");
}

#[test]
fn trigger_detection_matches_packet_contract() {
    let request = fs::read(packet_corpus("http_request.bin")).expect("http request");
    let redirect = fs::read(packet_corpus("http_redirect_response.bin")).expect("redirect");
    assert_eq!(
        detect_response_trigger(&request, &redirect),
        Some(TriggerEvent::Redirect)
    );

    let tls_request = fs::read(packet_corpus("tls_client_hello.bin")).expect("tls request");
    let tls_response = fs::read(packet_corpus("tls_server_hello_like.bin")).expect("tls response");
    assert_eq!(
        detect_response_trigger(&tls_request, &tls_response),
        Some(TriggerEvent::SslErr)
    );
}
