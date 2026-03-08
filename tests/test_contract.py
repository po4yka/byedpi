#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROXY_BINARY = ""
BIN_DIR = Path()
PROJECT_ROOT = Path()
HAS_FAKE_SUPPORT = sys.platform.startswith("linux") or sys.platform == "win32"


def run_command(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        check=False,
    )


def run_json_command(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> dict[str, object]:
    proc = run_command(args, env=env, cwd=cwd)
    if proc.returncode != 0:
        raise AssertionError(
            f"command failed ({proc.returncode}): {' '.join(args)}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
    return json.loads(proc.stdout)


def oracle(name: str) -> str:
    path = BIN_DIR / name
    if not path.exists():
        raise AssertionError(f"missing oracle binary: {path}")
    return str(path)


def packets_corpus(name: str) -> str:
    return str(PROJECT_ROOT / "tests" / "corpus" / "packets" / name)


def config_corpus(name: str) -> str:
    return str(PROJECT_ROOT / "tests" / "corpus" / "config" / name)


def binary_temp_file(data: bytes) -> tempfile.NamedTemporaryFile:
    tmp = tempfile.NamedTemporaryFile(prefix="ciadpi-oracle-", suffix=".bin", delete=False)
    tmp.write(data)
    tmp.flush()
    tmp.close()
    return tmp


class CliContractTests(unittest.TestCase):
    def test_help_contract(self) -> None:
        proc = run_command([PROXY_BINARY, "--help"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--no-domain", proc.stdout)
        self.assertIn("--cache-file", proc.stdout)

    def test_version_contract(self) -> None:
        proc = run_command([PROXY_BINARY, "--version"])
        self.assertEqual(proc.returncode, 0)
        self.assertRegex(proc.stdout.strip(), r"^\d+\.\d+$")

    def test_invalid_argument_fails(self) -> None:
        proc = run_command([PROXY_BINARY, "--definitely-invalid"])
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(proc.stderr or proc.stdout)


class ConfigOracleTests(unittest.TestCase):
    def test_parse_args_matches_env_contract(self) -> None:
        env = os.environ.copy()
        env["SS_LOCAL_PORT"] = "1443"
        env["SS_PLUGIN_OPTIONS"] = (
            "--no-domain --no-udp --auto torst --split 1+s "
            "--to-socks5 127.0.0.1:1081"
        )
        data = run_json_command([oracle("oracle_config"), "parse_args"], env=env)

        self.assertEqual(data["listen_port"], 1443)
        self.assertTrue(data["shadowsocks"])
        self.assertFalse(data["resolve"])
        self.assertFalse(data["udp"])
        self.assertTrue(data["delay_conn"])
        self.assertEqual(data["dp_n"], 2)
        self.assertEqual(data["actionable_group"], 1)
        group = data["groups"][1]
        self.assertEqual(group["detect"], 8)
        self.assertEqual(group["parts"][0]["mode"], 1)
        self.assertEqual(group["ext_socks"]["port"], 1081)

    @unittest.skipUnless(sys.platform.startswith("linux"), "protect_path auto-detection is Linux-only")
    def test_shadowsocks_protect_path_auto_detection(self) -> None:
        env = os.environ.copy()
        env["SS_LOCAL_PORT"] = "2443"
        with tempfile.TemporaryDirectory(prefix="ciadpi-protect-") as tmpdir:
            cwd = Path(tmpdir)
            (cwd / "protect_path").write_text("")
            data = run_json_command([oracle("oracle_config"), "parse_args"], env=env, cwd=cwd)
        self.assertEqual(data["listen_port"], 2443)
        self.assertEqual(data["protect_path"], "protect_path")

    def test_hosts_match_and_ipset_match(self) -> None:
        host_data = run_json_command(
            [oracle("oracle_config"), "hosts_match", config_corpus("hosts.txt"), "www.example.com"]
        )
        host_miss = run_json_command(
            [oracle("oracle_config"), "hosts_match", config_corpus("hosts.txt"), "not-example.net"]
        )
        ip_hit = run_json_command(
            [oracle("oracle_config"), "ipset_match", config_corpus("ipset.txt"), "10.1.2.3"]
        )
        ip_miss = run_json_command(
            [oracle("oracle_config"), "ipset_match", config_corpus("ipset.txt"), "192.168.1.1"]
        )

        self.assertTrue(host_data["matched"])
        self.assertFalse(host_miss["matched"])
        self.assertTrue(ip_hit["matched"])
        self.assertFalse(ip_miss["matched"])

    def test_cache_roundtrip_is_stable(self) -> None:
        proc = run_command([oracle("oracle_config"), "cache_roundtrip", config_corpus("cache_sample.txt")])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, Path(config_corpus("cache_sample.txt")).read_text())

    def test_parse_args_with_hosts_ipset_and_cache(self) -> None:
        data = run_json_command(
            [
                oracle("oracle_config"),
                "parse_args",
                "--hosts",
                config_corpus("hosts.txt"),
                "--ipset",
                config_corpus("ipset.txt"),
                "--cache-ttl",
                "60",
                "--cache-file",
                "-",
                "--auto",
                "torst",
                "--split",
                "1+s",
            ]
        )
        self.assertEqual(data["dp_n"], 3)
        group = data["groups"][0]
        self.assertEqual(group["hosts_count"], 2)
        self.assertEqual(group["ipset_count"], 2)
        self.assertEqual(group["cache_ttl"], 60)
        self.assertEqual(group["cache_file"], "-")

    def test_parse_args_with_extended_desync_flags(self) -> None:
        data = run_json_command(
            [
                oracle("oracle_config"),
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
            ]
        )
        self.assertEqual(data["listen_ip"], "127.0.0.1")
        self.assertEqual(data["listen_port"], 2080)
        self.assertEqual(data["bind_ip"], "127.0.0.1")
        self.assertEqual(data["max_open"], 33)
        self.assertEqual(data["bfsize"], 8192)
        self.assertTrue(data["http_connect"])
        group = data["groups"][0]
        self.assertEqual(group["proto"], 31)
        self.assertEqual(group["pf"], [80, 90])
        self.assertEqual(group["rounds"], [2, 4])
        self.assertEqual(group["ttl"], 3)
        self.assertEqual(group["fake_mod"], 3)
        self.assertEqual(group["fake_tls_size"], 128)
        self.assertGreater(group["fake_data_size"], 0)
        self.assertEqual(group["fake_offset"]["pos"], 1)
        self.assertEqual(group["fake_offset"]["flag"], 8)
        self.assertEqual(group["fake_sni_list"], [])
        self.assertEqual(group["oob_data"], "Z")
        self.assertEqual(group["mod_http"], 7)
        self.assertEqual(group["tlsminor"], 5)
        self.assertTrue(group["tlsminor_set"])
        self.assertEqual(group["udp_fake_count"], 2)

    @unittest.skipUnless(sys.platform.startswith("linux"), "md5sig/drop-sack/fake-sni are Linux-gated here")
    def test_parse_args_with_linux_fake_flags(self) -> None:
        data = run_json_command(
            [
                oracle("oracle_config"),
                "parse_args",
                "--md5sig",
                "--fake-sni",
                "docs.example.test",
                "--fake-sni",
                "static.example.test",
                "--drop-sack",
            ]
        )
        group = data["groups"][0]
        self.assertTrue(group["md5sig"])
        self.assertTrue(group["drop_sack"])
        self.assertEqual(group["fake_sni_list"], ["docs.example.test", "static.example.test"])

    def test_parse_args_invalid_value_fails(self) -> None:
        proc = run_command([oracle("oracle_config"), "parse_args", "--ttl", "999"])
        self.assertNotEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertFalse(data["ok"])


class ProtocolOracleTests(unittest.TestCase):
    def _temp_request(self, payload: bytes) -> str:
        tmp = tempfile.NamedTemporaryFile(prefix="ciadpi-proto-", suffix=".bin", delete=False)
        tmp.write(payload)
        tmp.flush()
        tmp.close()
        self.addCleanup(Path(tmp.name).unlink, missing_ok=True)
        return tmp.name

    def test_socks4_request_parser(self) -> None:
        payload = b"\x04\x01" + (8080).to_bytes(2, "big") + socket.inet_aton("127.0.0.1") + b"user\x00"
        data = run_json_command([oracle("oracle_protocol"), "socks4", self._temp_request(payload)])
        self.assertTrue(data["ok"])
        self.assertEqual(data["addr"]["family"], "ipv4")
        self.assertEqual(data["addr"]["addr"], "127.0.0.1")
        self.assertEqual(data["addr"]["port"], 8080)

    def test_socks5_connect_and_udp_parser(self) -> None:
        connect = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + (443).to_bytes(2, "big")
        dgram = b"\x05\x03\x00\x01" + socket.inet_aton("127.0.0.1") + (5353).to_bytes(2, "big")

        connect_data = run_json_command([oracle("oracle_protocol"), "socks5", self._temp_request(connect)])
        dgram_data = run_json_command(
            [oracle("oracle_protocol"), "socks5", self._temp_request(dgram), "dgram"]
        )

        self.assertTrue(connect_data["ok"])
        self.assertEqual(connect_data["addr"]["port"], 443)
        self.assertTrue(dgram_data["ok"])
        self.assertEqual(dgram_data["addr"]["port"], 5353)

    def test_http_connect_parser(self) -> None:
        payload = (
            b"CONNECT 127.0.0.1:8443 HTTP/1.1\r\n"
            b"Host: 127.0.0.1:8443\r\n"
            b"\r\n"
        )
        data = run_json_command([oracle("oracle_protocol"), "http_connect", self._temp_request(payload)])
        self.assertTrue(data["ok"])
        self.assertEqual(data["addr"]["addr"], "127.0.0.1")
        self.assertEqual(data["addr"]["port"], 8443)

    def test_socks4a_domain_parser(self) -> None:
        payload = b"\x04\x01" + (8081).to_bytes(2, "big") + b"\x00\x00\x00\x01" + b"user\x00localhost\x00"
        data = run_json_command([oracle("oracle_protocol"), "socks4", self._temp_request(payload)])
        self.assertTrue(data["ok"])
        self.assertEqual(data["addr"]["port"], 8081)

    def test_socks5_domain_and_ipv6_parser(self) -> None:
        domain = b"localhost"
        domain_payload = b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + (443).to_bytes(2, "big")
        ipv6_payload = b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1") + (9443).to_bytes(2, "big")

        domain_data = run_json_command([oracle("oracle_protocol"), "socks5", self._temp_request(domain_payload)])
        ipv6_data = run_json_command([oracle("oracle_protocol"), "socks5", self._temp_request(ipv6_payload)])

        self.assertTrue(domain_data["ok"])
        self.assertEqual(domain_data["addr"]["port"], 443)
        self.assertTrue(ipv6_data["ok"])
        self.assertEqual(ipv6_data["addr"]["family"], "ipv6")
        self.assertEqual(ipv6_data["addr"]["addr"], "::1")
        self.assertEqual(ipv6_data["addr"]["port"], 9443)

    def test_protocol_parser_rejects_invalid_socks5_request(self) -> None:
        data = run_json_command([oracle("oracle_protocol"), "socks5", self._temp_request(b"\x05\x01\x00")])
        self.assertFalse(data["ok"])


class DesyncOracleTests(unittest.TestCase):
    def parse_packet_oracle(self, command: str, payload: bytes, *args: str) -> dict[str, object]:
        tmp = binary_temp_file(payload)
        self.addCleanup(Path(tmp.name).unlink, missing_ok=True)
        return run_json_command([oracle("oracle_packets"), command, tmp.name, *args])

    def test_http_mod_and_split_plan(self) -> None:
        data = run_json_command(
            [
                oracle("oracle_desync"),
                packets_corpus("http_request.bin"),
                "7",
                "--mod-http",
                "rh",
                "--split",
                "8",
            ]
        )
        self.assertTrue(data["ok"])
        self.assertEqual(data["steps"][0]["mode"], 1)
        self.assertEqual(data["steps"][0]["end"], 8)
        self.assertEqual(len(data["tampered_hex"]), data["tampered_len"] * 2)

    def test_tls_record_split_plan(self) -> None:
        data = run_json_command(
            [
                oracle("oracle_desync"),
                packets_corpus("tls_client_hello.bin"),
                "7",
                "--tlsrec",
                "32",
            ]
        )
        original_len = len(Path(packets_corpus("tls_client_hello.bin")).read_bytes())
        self.assertTrue(data["ok"])
        self.assertEqual(data["tampered_len"], original_len + 5)
        self.assertEqual(data["proto_type"], 0)

    def test_tlsminor_mutation_plan(self) -> None:
        data = run_json_command(
            [
                oracle("oracle_desync"),
                "plan",
                packets_corpus("tls_client_hello.bin"),
                "7",
                "--tlsminor",
                "5",
            ]
        )
        self.assertTrue(data["ok"])
        self.assertTrue(data["tampered_hex"].startswith("160305"))

    def test_host_offset_plans_for_http_and_tls(self) -> None:
        http_plan = run_json_command(
            [
                oracle("oracle_desync"),
                "plan",
                packets_corpus("http_request.bin"),
                "7",
                "--split",
                "0+h",
            ]
        )
        tls_plan = run_json_command(
            [
                oracle("oracle_desync"),
                "plan",
                packets_corpus("tls_client_hello.bin"),
                "7",
                "--split",
                "0+s",
            ]
        )

        self.assertTrue(http_plan["ok"])
        self.assertEqual(http_plan["steps"][0]["end"], http_plan["host_pos"])
        self.assertTrue(tls_plan["ok"])
        self.assertEqual(tls_plan["steps"][0]["end"], tls_plan["host_pos"])

    def test_desync_modes_are_planned_distinctly(self) -> None:
        expected = {
            "--split": 1,
            "--disorder": 2,
            "--oob": 3,
            "--disoob": 4,
        }
        if HAS_FAKE_SUPPORT:
            expected["-f"] = 5
        for flag, mode in expected.items():
            with self.subTest(flag=flag):
                data = run_json_command(
                    [
                        oracle("oracle_desync"),
                        "plan",
                        packets_corpus("http_request.bin"),
                        "7",
                        flag,
                        "8",
                    ]
                )
                self.assertTrue(data["ok"])
                self.assertEqual(data["steps"][0]["mode"], mode)
                self.assertEqual(data["steps"][0]["end"], 8)

    @unittest.skipUnless(HAS_FAKE_SUPPORT, "fake packet builder requires FAKE_SUPPORT")
    def test_fake_packet_can_rewrite_tls_sni(self) -> None:
        data = run_json_command(
            [
                oracle("oracle_desync"),
                "fake",
                packets_corpus("tls_client_hello.bin"),
                "7",
                "-f",
                "-1",
                "--fake-sni",
                "docs.example.test",
                "--fake-tls-mod",
                "orig",
            ]
        )
        self.assertTrue(data["ok"])
        fake_bytes = bytes.fromhex(data["fake_hex"])
        parsed = self.parse_packet_oracle("parse_tls", fake_bytes)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["host"], "docs.example.test")

    @unittest.skipUnless(HAS_FAKE_SUPPORT, "fake packet builder requires FAKE_SUPPORT")
    def test_fake_packet_can_use_custom_http_payload(self) -> None:
        data = run_json_command(
            [
                oracle("oracle_desync"),
                "fake",
                packets_corpus("http_request.bin"),
                "7",
                "-f",
                "-1",
                "--fake-data",
                ":GET / HTTP/1.1\r\nHost: fake.example.test\r\n\r\n",
                "--fake-offset",
                "1+h",
            ]
        )
        self.assertTrue(data["ok"])
        self.assertGreaterEqual(data["fake_offset"], 1)
        fake_bytes = bytes.fromhex(data["fake_hex"])
        parsed = self.parse_packet_oracle("parse_http", fake_bytes)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["host"], "fake.example.test")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--bin-dir", required=True)
    parser.add_argument("--project-root", required=True)
    args = parser.parse_args()

    global PROXY_BINARY, BIN_DIR, PROJECT_ROOT
    PROXY_BINARY = args.binary
    BIN_DIR = Path(args.bin_dir).resolve()
    PROJECT_ROOT = Path(args.project_root).resolve()

    suite = unittest.TestSuite()
    for case in (
        CliContractTests,
        ConfigOracleTests,
        ProtocolOracleTests,
        DesyncOracleTests,
    ):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
