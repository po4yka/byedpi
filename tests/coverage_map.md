# Porting Coverage Map

This file freezes the current Linux-facing contract before the Rust cutover.

| Surface | Feature | Owner |
| --- | --- | --- |
| CLI | `--help`, `--version`, invalid args | `tests/test_contract.py::CliContractTests` |
| Env startup | `SS_LOCAL_PORT`, `SS_PLUGIN_OPTIONS`, Linux `protect_path` auto-detect | `tests/test_contract.py::ConfigOracleTests` |
| Config parsing | grouped `--auto`, `--split`, `--to-socks5`, cache flags, proto/pf/rounds/tlsminor/oob/mod-http/udp-fake/fake-data/fake-offset | `tests/test_contract.py::ConfigOracleTests` via `oracle_config` |
| Config parsing | Linux-only `md5sig`, `drop-sack`, `fake-sni` flags | `tests/test_contract.py::ConfigOracleTests.test_parse_args_with_linux_fake_flags` via `oracle_config` |
| Filters | hosts suffix matching, ipset CIDR matching | `tests/test_contract.py::ConfigOracleTests` via `oracle_config` |
| Cache format | dump/load round-trip | `tests/test_contract.py::ConfigOracleTests` via `oracle_config` |
| Protocol parsing | SOCKS4, SOCKS4a domain, SOCKS5 connect, SOCKS5 domain, SOCKS5 IPv6, SOCKS5 UDP associate, HTTP CONNECT, invalid requests | `tests/test_contract.py::ProtocolOracleTests` via `oracle_protocol` |
| Packets | HTTP/TLS parsing, redirects, TLS SID mismatch | `tests/test_packets.c`, `crates/ciadpi-packets/tests/oracle_diff.rs`, `tests/oracle_packets.c` |
| Packet mutations | HTTP header mutation, TLS split, TLS SNI rewrite (grow and shrink), deterministic TLS randomization | `tests/test_packets.c`, `crates/ciadpi-packets/tests/oracle_diff.rs`, `tests/oracle_packets.c` |
| Desync planning | deterministic split/mod-http/tlsrec/tlsminor planning, host/SNI offsets, split/disorder/oob/disoob mode selection | `tests/test_contract.py::DesyncOracleTests` via `oracle_desync` |
| Desync fake generation | deterministic fake packet builder for custom HTTP payloads and TLS SNI rewrites on `FAKE_SUPPORT` platforms | `tests/test_contract.py::DesyncOracleTests` via `oracle_desync fake` |
| Desync runtime | stream-visible `mod-http`, `tlsrec`, `tlsminor`, and `oob` behavior matches the C oracle and preserves upstream payload contracts | `tests/test_desync_runtime.py::DesyncRuntimeTests` |
| Linux wire behavior | loopback packet-capture assertions for `split`, `oob`, `disorder`, `disoob`, and `fake` send-side payload chunking, TTL, and URG flags | `tests/test_desync_runtime.py::LinuxWireCaptureTests` |
| Auto/runtime parity | cache-backed connect fallback plus `redirect`, `ssl_err`, and `torst` replay behavior match the C runtime contract | `tests/test_auto_runtime.py::AutoRuntimeTests` |
| Linux routed behavior | multi-namespace end-to-end assertions for `fake`, `md5sig`, and `drop-sack` confirm original payload delivery across routed loss/rejection paths | `tests/test_linux_routed_runtime.py::RoutedLinuxRuntimeTests` |
| Linux socket features | `--protect-path` passes outbound FDs to the helper socket and `--transparent` relays redirected traffic to the original destination | `tests/test_linux_runtime_features.py` |
| Rust desync runtime | `ciadpi-rs` passes the same desync runtime and Linux loopback wire suite as the C binary | `make test-rust-desync-runtime`, `tests/test_desync_runtime.py` |
| Rust auto/runtime parity | `ciadpi-rs` passes the same cache and auto-trigger replay suite as the C binary | `make test-rust-auto-runtime`, `tests/test_auto_runtime.py` |
| Rust routed desync runtime | `ciadpi-rs` passes the same routed Linux fake/md5sig/drop-sack suite as the C binary | `make test-rust-linux-routed-runtime`, `tests/test_linux_routed_runtime.py` |
| Rust Linux socket features | `ciadpi-rs` passes the same transparent/protect-path runtime suite as the C binary | `make test-rust-linux-runtime-features`, `tests/test_linux_runtime_features.py` |
| Rust binary parity | side-by-side `ciadpi` vs `ciadpi-rs` parity for `--help`, `--version`, and parse-failure surfaces; Rust dry-run acceptance for valid configs | `tests/test_rust_binary_parity.py`, `crates/ciadpi-bin/tests/cli.rs` |
| Rust runtime subset | `ciadpi-rs` SOCKS4, SOCKS5 CONNECT, HTTP CONNECT, SOCKS5 UDP associate, UDP fake bursts, TLS tunneling, churn, no-domain rejection, no-udp rejection, connect failure handling, SOCKS chaining, and IPv6 echo where available | `tests/test_rust_runtime_subset.py` |
| Proxy behavior | SOCKS4, SOCKS5, HTTP CONNECT, UDP associate, TLS tunneling, external SOCKS chaining, upstream connect failure handling, IPv6, `--no-domain`, `--no-udp`, `--udp-fake` bursts | `tests/test_proxy_integration.py` |
| Stress | connection churn over repeated proxied SOCKS5 sessions | `tests/test_proxy_integration.py::ProxyIntegrationTests.test_connection_churn_echo` |
| Safety | ASan/UBSan C builds, packet fuzz smoke, Rust property tests | `make test-sanitize`, `make fuzz-packets`, `crates/ciadpi-packets/src/lib.rs` |
| Performance smoke | packet hot-path benchmark smoke | `make bench-smoke`, `crates/ciadpi-packets/tests/benchmark_smoke.rs` |

## Planned follow-ups

- Promotion thresholds for churn and benchmark regressions once the Rust binary is the active runtime path.
