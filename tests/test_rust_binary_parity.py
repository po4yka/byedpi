#!/usr/bin/env python3

from __future__ import annotations

import argparse
import subprocess
import unittest


def run_command(binary: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [binary, *args],
        capture_output=True,
        text=True,
        check=False,
    )


class RustBinaryParityTests(unittest.TestCase):
    def test_help_surface_matches_core_contract(self) -> None:
        c_proc = run_command(C_BINARY, "--help")
        rust_proc = run_command(RUST_BINARY, "--help")

        self.assertEqual(c_proc.returncode, 0, c_proc.stderr)
        self.assertEqual(rust_proc.returncode, 0, rust_proc.stderr)
        for marker in ("--no-domain", "--cache-file", "--split", "--fake-offset"):
            with self.subTest(marker=marker):
                self.assertIn(marker, c_proc.stdout)
                self.assertIn(marker, rust_proc.stdout)

    def test_version_matches(self) -> None:
        c_proc = run_command(C_BINARY, "--version")
        rust_proc = run_command(RUST_BINARY, "--version")

        self.assertEqual(c_proc.returncode, 0, c_proc.stderr)
        self.assertEqual(rust_proc.returncode, 0, rust_proc.stderr)
        self.assertEqual(rust_proc.stdout.strip(), c_proc.stdout.strip())

    def test_invalid_argument_fails_in_both_binaries(self) -> None:
        c_proc = run_command(C_BINARY, "--definitely-invalid")
        rust_proc = run_command(RUST_BINARY, "--definitely-invalid")

        self.assertNotEqual(c_proc.returncode, 0)
        self.assertNotEqual(rust_proc.returncode, 0)
        self.assertTrue(c_proc.stderr or c_proc.stdout)
        self.assertTrue(rust_proc.stderr or rust_proc.stdout)

    def test_invalid_value_fails_in_both_binaries(self) -> None:
        c_proc = run_command(C_BINARY, "--ttl", "999")
        rust_proc = run_command(RUST_BINARY, "--ttl", "999")

        self.assertNotEqual(c_proc.returncode, 0)
        self.assertNotEqual(rust_proc.returncode, 0)
        self.assertIn("invalid value", c_proc.stderr + c_proc.stdout)
        self.assertIn("invalid value", rust_proc.stderr + rust_proc.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--c-binary", required=True)
    parser.add_argument("--rust-binary", required=True)
    args = parser.parse_args()

    global C_BINARY, RUST_BINARY
    C_BINARY = args.c_binary
    RUST_BINARY = args.rust_binary

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RustBinaryParityTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
