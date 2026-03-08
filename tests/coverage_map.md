# Porting Coverage Map

This file freezes the current Linux-facing contract before the Rust cutover.

| Surface | Feature | Owner |
| --- | --- | --- |
| CLI | `--help`, `--version`, invalid args | `tests/test_contract.py::CliContractTests` |
| Env startup | `SS_LOCAL_PORT`, `SS_PLUGIN_OPTIONS`, Linux `protect_path` auto-detect | `tests/test_contract.py::ConfigOracleTests` |
| Config parsing | grouped `--auto`, `--split`, `--to-socks5`, cache flags | `tests/test_contract.py::ConfigOracleTests` via `oracle_config` |
| Filters | hosts suffix matching, ipset CIDR matching | `tests/test_contract.py::ConfigOracleTests` via `oracle_config` |
| Cache format | dump/load round-trip | `tests/test_contract.py::ConfigOracleTests` via `oracle_config` |
| Protocol parsing | SOCKS4, SOCKS5 connect, SOCKS5 UDP associate, HTTP CONNECT | `tests/test_contract.py::ProtocolOracleTests` via `oracle_protocol` |
| Packets | HTTP/TLS parsing, redirects, TLS SID mismatch | `tests/test_packets.c`, `crates/ciadpi-packets/tests/oracle_diff.rs`, `tests/oracle_packets.c` |
| Packet mutations | HTTP header mutation, TLS split, TLS SNI rewrite, deterministic TLS randomization | `tests/test_packets.c`, `crates/ciadpi-packets/tests/oracle_diff.rs`, `tests/oracle_packets.c` |
| Desync planning | deterministic split/mod-http/tlsrec planning | `tests/test_contract.py::DesyncOracleTests` via `oracle_desync` |
| Proxy behavior | SOCKS4, SOCKS5, HTTP CONNECT, UDP associate, TLS tunneling, external SOCKS chaining, IPv6, `--no-domain`, `--no-udp` | `tests/test_proxy_integration.py` |
| Stress | connection churn over repeated proxied SOCKS5 sessions | `tests/test_proxy_integration.py::ProxyIntegrationTests.test_connection_churn_echo` |
| Safety | ASan/UBSan C builds, packet fuzz smoke, Rust property tests | `make test-sanitize`, `make fuzz-packets`, `crates/ciadpi-packets/src/lib.rs` |
| Performance smoke | packet hot-path benchmark smoke | `make bench-smoke`, `crates/ciadpi-packets/tests/benchmark_smoke.rs` |

## Planned follow-ups

- Linux wire-capture assertions for `split`, `disorder`, `oob`, `disoob`, `fake`, `tlsrec`, `tlsminor`, TTL handling, `md5sig`, and `drop-sack`.
- Promotion thresholds for churn and benchmark regressions once the Rust binary is the active runtime path.
