use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use ciadpi_config::{
    dump_cache_entries, load_cache_entries, parse_cli, parse_hosts_spec, parse_ipset_spec,
    FilterSet, ParseOutcome, StartupEnv,
};
use serde_json::Value;
#[cfg(target_os = "linux")]
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn oracle_bin() -> PathBuf {
    repo_root().join("tests").join("bin").join("oracle_config")
}

fn config_corpus(name: &str) -> PathBuf {
    repo_root().join("tests").join("corpus").join("config").join(name)
}

fn run_oracle(args: &[&str], envs: &[(&str, &str)], cwd: Option<&Path>) -> Value {
    let oracle = oracle_bin();
    assert!(
        oracle.exists(),
        "missing config oracle at {}. Run `make oracles` first.",
        oracle.display()
    );
    let mut command = Command::new(&oracle);
    command.args(args);
    command.envs(envs.iter().copied());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command.output().expect("oracle invocation");
    assert!(
        output.status.success(),
        "oracle failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("oracle json")
}

fn run_oracle_allow_failure(args: &[&str], envs: &[(&str, &str)], cwd: Option<&Path>) -> Value {
    let oracle = oracle_bin();
    assert!(
        oracle.exists(),
        "missing config oracle at {}. Run `make oracles` first.",
        oracle.display()
    );
    let mut command = Command::new(&oracle);
    command.args(args);
    command.envs(envs.iter().copied());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command.output().expect("oracle invocation");
    assert!(
        !output.stdout.is_empty(),
        "oracle returned no json: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("oracle json")
}

fn parse_runtime(args: &[&str], startup: StartupEnv) -> ciadpi_config::RuntimeConfig {
    let args: Vec<String> = args.iter().map(|value| (*value).to_owned()).collect();
    let parsed = parse_cli(&args, &startup).expect("rust parse");
    assert_eq!(parsed.outcome, ParseOutcome::Run);
    parsed.config.expect("runtime config")
}

#[test]
fn parse_args_matches_env_contract() {
    let plugin = "--no-domain --no-udp --auto torst --split 1+s --to-socks5 127.0.0.1:1081";
    let oracle = run_oracle(
        &["parse_args"],
        &[("SS_LOCAL_PORT", "1443"), ("SS_PLUGIN_OPTIONS", plugin)],
        None,
    );
    let rust = parse_runtime(
        &[],
        StartupEnv {
            ss_local_port: Some("1443".to_owned()),
            ss_plugin_options: Some(plugin.to_owned()),
            protect_path_present: false,
        },
    );

    assert_eq!(rust.listen.listen_port as u64, oracle["listen_port"].as_u64().unwrap());
    assert_eq!(rust.shadowsocks, oracle["shadowsocks"].as_bool().unwrap());
    assert_eq!(rust.resolve, oracle["resolve"].as_bool().unwrap());
    assert_eq!(rust.udp, oracle["udp"].as_bool().unwrap());
    assert_eq!(rust.delay_conn, oracle["delay_conn"].as_bool().unwrap());
    assert_eq!(rust.groups.len() as u64, oracle["dp_n"].as_u64().unwrap());
    assert_eq!(rust.actionable_group() as u64, oracle["actionable_group"].as_u64().unwrap());
    let group = &rust.groups[1];
    assert_eq!(group.detect as u64, oracle["groups"][1]["detect"].as_u64().unwrap());
    assert_eq!(group.parts[0].mode as u64, oracle["groups"][1]["parts"][0]["mode"].as_u64().unwrap());
    assert_eq!(
        group.ext_socks.expect("ext socks").addr.port() as u64,
        oracle["groups"][1]["ext_socks"]["port"].as_u64().unwrap()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn shadowsocks_protect_path_auto_detection_matches_oracle() {
    let temp = tempdir().expect("tempdir");
    fs::write(temp.path().join("protect_path"), "").expect("protect_path");
    let oracle = run_oracle(&["parse_args"], &[("SS_LOCAL_PORT", "2443")], Some(temp.path()));
    let rust = parse_runtime(
        &[],
        StartupEnv {
            ss_local_port: Some("2443".to_owned()),
            ss_plugin_options: None,
            protect_path_present: true,
        },
    );
    assert_eq!(rust.listen.listen_port as u64, oracle["listen_port"].as_u64().unwrap());
    assert_eq!(
        rust.protect_path.as_deref(),
        oracle["protect_path"].as_str()
    );
}

#[test]
fn hosts_and_ipset_matching_match_oracle() {
    let hosts_spec = fs::read_to_string(config_corpus("hosts.txt")).expect("hosts");
    let ipset_spec = fs::read_to_string(config_corpus("ipset.txt")).expect("ipset");
    let filter = FilterSet {
        hosts: parse_hosts_spec(&hosts_spec).expect("parse hosts"),
        ipset: parse_ipset_spec(&ipset_spec).expect("parse ipset"),
    };

    let host_hit = run_oracle(
        &[
            "hosts_match",
            config_corpus("hosts.txt").to_str().unwrap(),
            "www.example.com",
        ],
        &[],
        None,
    );
    let host_miss = run_oracle(
        &[
            "hosts_match",
            config_corpus("hosts.txt").to_str().unwrap(),
            "not-example.net",
        ],
        &[],
        None,
    );
    let ip_hit = run_oracle(
        &[
            "ipset_match",
            config_corpus("ipset.txt").to_str().unwrap(),
            "10.1.2.3",
        ],
        &[],
        None,
    );
    let ip_miss = run_oracle(
        &[
            "ipset_match",
            config_corpus("ipset.txt").to_str().unwrap(),
            "192.168.1.1",
        ],
        &[],
        None,
    );

    assert_eq!(filter.hosts_match("www.example.com"), host_hit["matched"].as_bool().unwrap());
    assert_eq!(filter.hosts_match("not-example.net"), host_miss["matched"].as_bool().unwrap());
    assert_eq!(
        filter.ipset_match("10.1.2.3".parse().unwrap()),
        ip_hit["matched"].as_bool().unwrap()
    );
    assert_eq!(
        filter.ipset_match("192.168.1.1".parse().unwrap()),
        ip_miss["matched"].as_bool().unwrap()
    );
}

#[test]
fn cache_roundtrip_is_stable() {
    let sample = fs::read_to_string(config_corpus("cache_sample.txt")).expect("cache sample");
    let entries = load_cache_entries(&sample);
    assert_eq!(dump_cache_entries(&entries), sample);
}

#[test]
fn parse_args_with_hosts_ipset_and_cache_matches_oracle() {
    let hosts = config_corpus("hosts.txt");
    let ipset = config_corpus("ipset.txt");
    let args = [
        "--hosts",
        hosts.to_str().unwrap(),
        "--ipset",
        ipset.to_str().unwrap(),
        "--cache-ttl",
        "60",
        "--cache-file",
        "-",
        "--auto",
        "torst",
        "--split",
        "1+s",
    ];
    let oracle = run_oracle(
        &[
            "parse_args",
            "--hosts",
            hosts.to_str().unwrap(),
            "--ipset",
            ipset.to_str().unwrap(),
            "--cache-ttl",
            "60",
            "--cache-file",
            "-",
            "--auto",
            "torst",
            "--split",
            "1+s",
        ],
        &[],
        None,
    );
    let rust = parse_runtime(&args, StartupEnv::default());

    assert_eq!(rust.groups.len() as u64, oracle["dp_n"].as_u64().unwrap());
    let group = &rust.groups[0];
    assert_eq!(group.filters.hosts.len() as u64, oracle["groups"][0]["hosts_count"].as_u64().unwrap());
    assert_eq!(group.filters.ipset.len() as u64, oracle["groups"][0]["ipset_count"].as_u64().unwrap());
    assert_eq!(group.cache_ttl as u64, oracle["groups"][0]["cache_ttl"].as_u64().unwrap());
    assert_eq!(group.cache_file.as_deref(), oracle["groups"][0]["cache_file"].as_str());
}

#[test]
fn parse_args_with_extended_desync_flags_matches_oracle() {
    let args = [
        "--http-connect",
        "--ip",
        "127.0.0.1",
        "--port",
        "2080",
        "--conn-ip",
        "127.0.0.1",
        "--max-conn",
        "33",
        "--buf-size",
        "8192",
        "--proto",
        "t,h,u,i",
        "--pf",
        "80-90",
        "--round",
        "2-4",
        "--ttl",
        "3",
        "--fake-offset",
        "1+s",
        "--fake-tls-mod",
        "rand,orig,m=128",
        "--fake-data",
        ":GET / HTTP/1.1\r\nHost: fake.example.test\r\n\r\n",
        "--oob-data",
        "Z",
        "--mod-http",
        "h,d,r",
        "--tlsminor",
        "5",
        "--udp-fake",
        "2",
    ];
    let oracle = run_oracle(
        &[
            "parse_args",
            "--http-connect",
            "--ip",
            "127.0.0.1",
            "--port",
            "2080",
            "--conn-ip",
            "127.0.0.1",
            "--max-conn",
            "33",
            "--buf-size",
            "8192",
            "--proto",
            "t,h,u,i",
            "--pf",
            "80-90",
            "--round",
            "2-4",
            "--ttl",
            "3",
            "--fake-offset",
            "1+s",
            "--fake-tls-mod",
            "rand,orig,m=128",
            "--fake-data",
            ":GET / HTTP/1.1\r\nHost: fake.example.test\r\n\r\n",
            "--oob-data",
            "Z",
            "--mod-http",
            "h,d,r",
            "--tlsminor",
            "5",
            "--udp-fake",
            "2",
        ],
        &[],
        None,
    );
    let rust = parse_runtime(&args, StartupEnv::default());
    let group = &rust.groups[0];

    assert_eq!(rust.listen.listen_ip.to_string(), oracle["listen_ip"].as_str().unwrap());
    assert_eq!(rust.listen.listen_port as u64, oracle["listen_port"].as_u64().unwrap());
    assert_eq!(rust.listen.bind_ip.to_string(), oracle["bind_ip"].as_str().unwrap());
    assert_eq!(rust.max_open as u64, oracle["max_open"].as_u64().unwrap());
    assert_eq!(rust.buffer_size as u64, oracle["bfsize"].as_u64().unwrap());
    assert_eq!(rust.http_connect, oracle["http_connect"].as_bool().unwrap());
    assert_eq!(group.proto as u64, oracle["groups"][0]["proto"].as_u64().unwrap());
    assert_eq!(group.port_filter, Some((80, 90)));
    assert_eq!(group.rounds, [2, 4]);
    assert_eq!(group.ttl, Some(3));
    assert_eq!(group.fake_mod as u64, oracle["groups"][0]["fake_mod"].as_u64().unwrap());
    assert_eq!(group.fake_tls_size as u64, oracle["groups"][0]["fake_tls_size"].as_u64().unwrap());
    assert_eq!(group.fake_data.as_ref().map(Vec::len).unwrap() > 0, oracle["groups"][0]["fake_data_size"].as_u64().unwrap() > 0);
    let fake_offset = group.fake_offset.expect("fake offset");
    assert_eq!(fake_offset.pos as i64, oracle["groups"][0]["fake_offset"]["pos"].as_i64().unwrap());
    assert_eq!(fake_offset.flag as u64, oracle["groups"][0]["fake_offset"]["flag"].as_u64().unwrap());
    assert!(group.fake_sni_list.is_empty());
    assert_eq!(group.oob_data, Some(b'Z'));
    assert_eq!(group.mod_http as u64, oracle["groups"][0]["mod_http"].as_u64().unwrap());
    assert_eq!(group.tlsminor, Some(5));
    assert_eq!(group.udp_fake_count as u64, oracle["groups"][0]["udp_fake_count"].as_u64().unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn parse_args_with_linux_fake_flags_matches_oracle() {
    let args = [
        "--md5sig",
        "--fake-sni",
        "docs.example.test",
        "--fake-sni",
        "static.example.test",
        "--drop-sack",
    ];
    let oracle = run_oracle(
        &[
            "parse_args",
            "--md5sig",
            "--fake-sni",
            "docs.example.test",
            "--fake-sni",
            "static.example.test",
            "--drop-sack",
        ],
        &[],
        None,
    );
    let rust = parse_runtime(&args, StartupEnv::default());
    let group = &rust.groups[0];

    assert_eq!(group.md5sig, oracle["groups"][0]["md5sig"].as_bool().unwrap());
    assert_eq!(group.drop_sack, oracle["groups"][0]["drop_sack"].as_bool().unwrap());
    assert_eq!(
        group.fake_sni_list,
        oracle["groups"][0]["fake_sni_list"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
}

#[test]
fn invalid_value_matches_oracle_failure() {
    let oracle = run_oracle_allow_failure(&["parse_args", "--ttl", "999"], &[], None);
    let rust = parse_cli(
        &["--ttl".to_owned(), "999".to_owned()],
        &StartupEnv::default(),
    );
    assert_eq!(oracle["ok"].as_bool().unwrap(), false);
    assert!(rust.is_err());
}
