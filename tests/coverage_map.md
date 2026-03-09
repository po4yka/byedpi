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
| Desync runtime | stream-visible `mod-http`, `tlsrec`, `tlsminor`, `oob`, and staged `--wait-send` behavior matches the C oracle and preserves upstream payload contracts | `tests/test_desync_runtime.py::DesyncRuntimeTests` |
| Linux wire behavior | loopback packet-capture assertions for `split`, `oob`, `disorder`, `disoob`, and `fake` send-side payload chunking, TTL, URG flags, and staged-send delay timing | `tests/test_desync_runtime.py::LinuxWireCaptureTests` |
| Auto/runtime parity | `AUTO_NOPOST` / `AUTO_SORT`, cache promotion and reuse, cache-backed connect fallback, `redirect`, `ssl_err`, `torst`, and partial-TLS timeout count/byte-limit behavior match the C runtime contract | `tests/test_auto_runtime.py::AutoRuntimeTests` |
| Linux routed behavior | multi-namespace end-to-end assertions for `fake`, `md5sig`, and `drop-sack` confirm original payload delivery across routed loss/rejection paths | `tests/test_linux_routed_runtime.py::RoutedLinuxRuntimeTests` |
| Linux socket features | `--protect-path` passes outbound FDs to the helper socket and `--transparent` relays redirected traffic to the original destination | `tests/test_linux_runtime_features.py` |
| Rust desync runtime | default `ciadpi` (Rust) passes the same desync runtime and Linux loopback wire suite as the hidden C oracle runtime | `make test-desync-runtime`, `tests/test_desync_runtime.py` |
| Rust auto/runtime parity | default `ciadpi` (Rust) passes the same cache, auto-trigger replay, and partial-timeout policy suite as the hidden C oracle runtime | `make test-auto-runtime`, `tests/test_auto_runtime.py` |
| Rust routed desync runtime | default `ciadpi` (Rust) passes the same routed Linux fake/md5sig/drop-sack suite as the hidden C oracle runtime | `make test-linux-routed-runtime`, `tests/test_linux_routed_runtime.py` |
| Rust Linux socket features | default `ciadpi` (Rust) passes the same transparent/protect-path runtime suite as the hidden C oracle runtime | `make test-linux-runtime-features`, `tests/test_linux_runtime_features.py` |
| Rust runtime migration | default `ciadpi` (Rust) pidfile handling, TCP Fast Open, delayed connect, cache stdout dumping, max-conn admission, and Shadowsocks env startup behave like the C binary | `make test-rust-runtime-migration`, `tests/test_rust_runtime_migration.py` |
| Rust binary parity | side-by-side default `ciadpi` (Rust) vs hidden C oracle runtime parity for `--help`, `--version`, and parse-failure surfaces | `make test-rust-binary-parity`, `tests/test_rust_binary_parity.py`, `crates/ciadpi-bin/tests/cli.rs` |
| Rust runtime subset | default `ciadpi` (Rust) covers SOCKS4, SOCKS5 CONNECT, HTTP CONNECT, SOCKS5 UDP associate, UDP fake bursts, TLS tunneling, churn, no-domain rejection, no-udp rejection, connect failure handling, SOCKS chaining, and IPv6 echo where available | `make test-rust-runtime`, `tests/test_rust_runtime_subset.py` |
| Install/package cutover | `make install` ships the Rust `ciadpi` binary and does not install hidden oracle artifacts | `make test-install-cutover`, `tests/test_install_cutover.py` |
| Windows cross-target buildability | Rust workspace test binaries link for `x86_64-pc-windows-gnu` so deferred Windows port regressions fail fast before runtime validation | `make test-windows-cross-check`, `.github/workflows/ci.yml` |
| Proxy behavior | SOCKS4, SOCKS5, HTTP CONNECT, UDP associate, TLS tunneling, external SOCKS chaining, upstream connect failure handling, IPv6, `--no-domain`, `--no-udp`, `--udp-fake` bursts | `tests/test_proxy_integration.py` |
| Stress | connection churn over repeated proxied SOCKS5 sessions | `tests/test_proxy_integration.py::ProxyIntegrationTests.test_connection_churn_echo` |
| Safety | ASan/UBSan C builds, packet fuzz smoke, Rust property tests | `make test-sanitize`, `make fuzz-packets`, `crates/ciadpi-packets/src/lib.rs` |
| Performance smoke | packet hot-path benchmark smoke | `make bench-smoke`, `crates/ciadpi-packets/tests/benchmark_smoke.rs` |

## Planned follow-ups

- Promotion thresholds for churn and benchmark regressions now that the Rust binary is the active Linux runtime path.
- Removal plan for the hidden C oracle runtime after the transition release window ends.
- Deferred Windows runtime and service migration after the Linux cutover is stable.
