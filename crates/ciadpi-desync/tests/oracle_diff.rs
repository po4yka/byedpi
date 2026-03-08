use std::fs;
use std::path::PathBuf;
use std::process::Command;

use ciadpi_config::{parse_cli, ParseOutcome, RuntimeConfig, StartupEnv};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use ciadpi_desync::build_fake_packet;
use ciadpi_desync::{plan_tcp, plan_udp, DesyncAction};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn oracle_bin() -> PathBuf {
    repo_root().join("tests").join("bin").join("oracle_desync")
}

fn packet_corpus(name: &str) -> PathBuf {
    repo_root().join("tests").join("corpus").join("packets").join(name)
}

fn run_oracle(args: &[&str]) -> Value {
    let oracle = oracle_bin();
    assert!(
        oracle.exists(),
        "missing desync oracle at {}. Run `make oracles` first.",
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

fn parse_group(args: &[&str]) -> (RuntimeConfig, usize) {
    let args: Vec<String> = args.iter().map(|value| (*value).to_owned()).collect();
    let parsed = parse_cli(&args, &StartupEnv::default()).expect("parse config");
    assert_eq!(parsed.outcome, ParseOutcome::Run);
    let config = parsed.config.expect("config");
    let idx = config.actionable_group();
    (config, idx)
}

fn hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[test]
fn mod_http_and_split_plan_matches_oracle() {
    let packet = packet_corpus("http_request.bin");
    let payload = fs::read(&packet).expect("packet");
    let oracle = run_oracle(&["plan", packet.to_str().unwrap(), "7", "--mod-http", "rh", "--split", "8"]);
    let (config, idx) = parse_group(&["--mod-http", "rh", "--split", "8"]);
    let plan = plan_tcp(&config.groups[idx], &payload, 7, config.default_ttl).expect("plan");

    assert_eq!(hex(&plan.tampered), oracle["tampered_hex"].as_str().unwrap());
    assert_eq!(plan.steps[0].mode as u64, oracle["steps"][0]["mode"].as_u64().unwrap());
    assert_eq!(plan.steps[0].end as i64, oracle["steps"][0]["end"].as_i64().unwrap());
}

#[test]
fn tls_record_split_plan_matches_oracle() {
    let packet = packet_corpus("tls_client_hello.bin");
    let payload = fs::read(&packet).expect("packet");
    let oracle = run_oracle(&["plan", packet.to_str().unwrap(), "7", "--tlsrec", "32"]);
    let (config, idx) = parse_group(&["--tlsrec", "32"]);
    let plan = plan_tcp(&config.groups[idx], &payload, 7, config.default_ttl).expect("plan");

    assert_eq!(plan.tampered.len() as u64, oracle["tampered_len"].as_u64().unwrap());
    assert_eq!(hex(&plan.tampered), oracle["tampered_hex"].as_str().unwrap());
}

#[test]
fn tlsminor_plan_matches_oracle() {
    let packet = packet_corpus("tls_client_hello.bin");
    let payload = fs::read(&packet).expect("packet");
    let oracle = run_oracle(&["plan", packet.to_str().unwrap(), "7", "--tlsminor", "5"]);
    let (config, idx) = parse_group(&["--tlsminor", "5"]);
    let plan = plan_tcp(&config.groups[idx], &payload, 7, config.default_ttl).expect("plan");

    assert_eq!(hex(&plan.tampered), oracle["tampered_hex"].as_str().unwrap());
}

#[test]
fn host_offset_plans_match_oracle() {
    let http_packet = packet_corpus("http_request.bin");
    let http_payload = fs::read(&http_packet).expect("http payload");
    let http_oracle = run_oracle(&["plan", http_packet.to_str().unwrap(), "7", "--split", "0+h"]);
    let (http_config, http_idx) = parse_group(&["--split", "0+h"]);
    let http_plan = plan_tcp(&http_config.groups[http_idx], &http_payload, 7, http_config.default_ttl)
        .expect("http plan");

    assert_eq!(http_plan.steps[0].end as i64, http_oracle["steps"][0]["end"].as_i64().unwrap());

    let tls_packet = packet_corpus("tls_client_hello.bin");
    let tls_payload = fs::read(&tls_packet).expect("tls payload");
    let tls_oracle = run_oracle(&["plan", tls_packet.to_str().unwrap(), "7", "--split", "0+s"]);
    let (tls_config, tls_idx) = parse_group(&["--split", "0+s"]);
    let tls_plan = plan_tcp(&tls_config.groups[tls_idx], &tls_payload, 7, tls_config.default_ttl)
        .expect("tls plan");

    assert_eq!(tls_plan.steps[0].end as i64, tls_oracle["steps"][0]["end"].as_i64().unwrap());
}

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn fake_packet_can_rewrite_tls_sni() {
    let packet = packet_corpus("tls_client_hello.bin");
    let payload = fs::read(&packet).expect("packet");
    let oracle = run_oracle(&[
        "fake",
        packet.to_str().unwrap(),
        "7",
        "-f",
        "-1",
        "--fake-sni",
        "docs.example.test",
        "--fake-tls-mod",
        "orig",
    ]);
    let (config, idx) = parse_group(&["-f", "-1", "--fake-sni", "docs.example.test", "--fake-tls-mod", "orig"]);
    let fake = build_fake_packet(&config.groups[idx], &payload, 7).expect("fake plan");

    assert_eq!(hex(&fake.bytes), oracle["fake_hex"].as_str().unwrap());
    assert_eq!(fake.fake_offset as u64, oracle["fake_offset"].as_u64().unwrap());
}

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn fake_packet_can_use_custom_http_payload() {
    let packet = packet_corpus("http_request.bin");
    let payload = fs::read(&packet).expect("packet");
    let oracle = run_oracle(&[
        "fake",
        packet.to_str().unwrap(),
        "7",
        "-f",
        "-1",
        "--fake-data",
        ":GET / HTTP/1.1\r\nHost: fake.example.test\r\n\r\n",
        "--fake-offset",
        "1+h",
    ]);
    let (config, idx) = parse_group(&[
        "-f",
        "-1",
        "--fake-data",
        ":GET / HTTP/1.1\r\nHost: fake.example.test\r\n\r\n",
        "--fake-offset",
        "1+h",
    ]);
    let fake = build_fake_packet(&config.groups[idx], &payload, 7).expect("fake plan");

    assert_eq!(hex(&fake.bytes), oracle["fake_hex"].as_str().unwrap());
    assert_eq!(fake.fake_offset as u64, oracle["fake_offset"].as_u64().unwrap());
}

#[test]
fn udp_fake_actions_are_deterministic() {
    let (config, idx) = parse_group(&["--udp-fake", "2"]);
    let actions = plan_udp(&config.groups[idx], b"udp proxy payload", config.default_ttl);
    assert_eq!(
        actions,
        vec![
            DesyncAction::SetTtl(8),
            DesyncAction::Write(vec![0; 64]),
            DesyncAction::Write(vec![0; 64]),
            DesyncAction::RestoreDefaultTtl,
            DesyncAction::Write(b"udp proxy payload".to_vec()),
        ]
    );
}
