use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use ciadpi_packets::{
    change_tls_sni_seeded_like_c, is_http_redirect, mod_http_like_c, parse_http, parse_tls,
    part_tls_like_c, randomize_tls_seeded_like_c, tls_session_id_mismatch, MH_HMIX, MH_SPACE,
};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn corpus_path(name: &str) -> PathBuf {
    repo_root().join("tests").join("corpus").join("packets").join(name)
}

fn oracle_bin() -> PathBuf {
    repo_root().join("tests").join("bin").join("oracle_packets")
}

fn run_oracle(args: &[&str]) -> Value {
    let oracle = oracle_bin();
    assert!(
        oracle.exists(),
        "missing packet oracle at {}. Run `make oracles` first.",
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

fn read_corpus(name: &str) -> Vec<u8> {
    fs::read(corpus_path(name)).expect("corpus file")
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

fn path_arg(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

#[test]
fn parse_http_matches_oracle() {
    let path = corpus_path("http_request.bin");
    let oracle = run_oracle(&["parse_http", path_arg(&path)]);
    let data = read_corpus("http_request.bin");
    let parsed = parse_http(&data).expect("rust parse_http");

    assert_eq!(oracle["ok"], Value::Bool(true));
    assert_eq!(parsed.host, oracle["host"].as_str().unwrap().as_bytes());
    assert_eq!(parsed.port, oracle["port"].as_u64().unwrap() as u16);
}

#[test]
fn parse_tls_matches_oracle() {
    let path = corpus_path("tls_client_hello.bin");
    let oracle = run_oracle(&["parse_tls", path_arg(&path)]);
    let data = read_corpus("tls_client_hello.bin");
    let parsed = parse_tls(&data).expect("rust parse_tls");

    assert_eq!(oracle["ok"], Value::Bool(true));
    assert_eq!(parsed, oracle["host"].as_str().unwrap().as_bytes());
}

#[test]
fn http_redirect_matches_oracle() {
    let req_path = corpus_path("http_request.bin");
    let resp_path = corpus_path("http_redirect_response.bin");
    let oracle = run_oracle(&[
        "is_http_redirect",
        path_arg(&req_path),
        path_arg(&resp_path),
    ]);
    let req = read_corpus("http_request.bin");
    let resp = read_corpus("http_redirect_response.bin");
    assert_eq!(Value::Bool(is_http_redirect(&req, &resp)), oracle["ok"]);
}

#[test]
fn tls_session_id_mismatch_matches_oracle() {
    let req_path = corpus_path("tls_client_hello.bin");
    let resp_path = corpus_path("tls_server_hello_like.bin");
    let oracle = run_oracle(&["neq_tls_sid", path_arg(&req_path), path_arg(&resp_path)]);
    let req = read_corpus("tls_client_hello.bin");
    let resp = read_corpus("tls_server_hello_like.bin");
    assert_eq!(Value::Bool(tls_session_id_mismatch(&req, &resp)), oracle["ok"]);
}

#[test]
fn mod_http_matches_oracle() {
    let path = corpus_path("http_request.bin");
    let oracle = run_oracle(&["mod_http", path_arg(&path), "3"]);
    let data = read_corpus("http_request.bin");
    let rust = mod_http_like_c(&data, MH_HMIX | MH_SPACE);

    assert_eq!(rust.rc, oracle["rc"].as_i64().unwrap() as isize);
    assert_eq!(hex(&rust.bytes), oracle["hex"].as_str().unwrap());
}

#[test]
fn part_tls_matches_oracle() {
    let path = corpus_path("tls_client_hello.bin");
    let oracle = run_oracle(&["part_tls", path_arg(&path), "32"]);
    let data = read_corpus("tls_client_hello.bin");
    let rust = part_tls_like_c(&data, 32);

    assert_eq!(rust.rc, oracle["rc"].as_i64().unwrap() as isize);
    assert_eq!(hex(&rust.bytes), oracle["hex"].as_str().unwrap());
}

#[test]
fn change_tls_sni_matches_oracle() {
    let path = corpus_path("tls_client_hello_ech.bin");
    let data = read_corpus("tls_client_hello_ech.bin");
    let capacity = data.len() + 64;
    let oracle = run_oracle(&[
        "change_tls_sni",
        path_arg(&path),
        "docs.example.test",
        &capacity.to_string(),
    ]);
    let rust = change_tls_sni_seeded_like_c(&data, b"docs.example.test", capacity, 1);

    assert_eq!(rust.rc, oracle["rc"].as_i64().unwrap() as isize);
    assert_eq!(hex(&rust.bytes), oracle["hex"].as_str().unwrap());
}

#[test]
fn randomize_tls_matches_deterministic_oracle() {
    let path = corpus_path("tls_client_hello.bin");
    let oracle = run_oracle(&["randomize_tls_seeded", path_arg(&path), "7"]);
    let data = read_corpus("tls_client_hello.bin");
    let rust = randomize_tls_seeded_like_c(&data, 7);

    assert_eq!(rust.rc, oracle["rc"].as_i64().unwrap() as isize);
    assert_eq!(hex(&rust.bytes), oracle["hex"].as_str().unwrap());
}
