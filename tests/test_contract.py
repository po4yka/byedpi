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


class DesyncOracleTests(unittest.TestCase):
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
