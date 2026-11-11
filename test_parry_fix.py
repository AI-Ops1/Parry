#!/usr/bin/env python3
"""
TDD Test Suite for Parry Auto-Remediation (--fix, fix subcommand, JSON format & MCP)
"""

import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import parry


class TestParryAutoRemediation(unittest.TestCase):
    def test_remediation_computed_for_hallucinated_apis(self) -> None:
        """Verify that findings include prompt_injection_patch and deterministic suggested_replacement."""
        ts_code = "const buf = new Buffer(1024);\nconst name = str.substr(0, 5);\n"
        findings = parry.scan_source(ts_code, "test.ts", "typescript")
        self.assertEqual(len(findings), 2)

        buf_finding = next(f for f in findings if f.rule_id == "PARRY-HAL-TS002")
        self.assertIsNotNone(buf_finding.prompt_injection_patch)
        self.assertIn("Buffer.alloc", buf_finding.suggested_replacement or "")

        substr_finding = next(f for f in findings if f.rule_id == "PARRY-HAL-TS001")
        self.assertIsNotNone(substr_finding.prompt_injection_patch)
        self.assertIn(".slice(", substr_finding.suggested_replacement or "")

    def test_python_datetime_utcnow_remediation(self) -> None:
        """Verify datetime.utcnow() is replaced with datetime.now(datetime.timezone.utc)."""
        py_code = "from datetime import datetime\nnow = datetime.utcnow()\n"
        findings = parry.scan_source(py_code, "test.py", "python")
        utc_finding = next(f for f in findings if f.rule_id == "PARRY-HAL-PY004")
        self.assertIsNotNone(utc_finding.prompt_injection_patch)
        self.assertIn("datetime.now(datetime.timezone.utc)", utc_finding.suggested_replacement or "")

    def test_rust_and_security_remediations(self) -> None:
        """Verify Rust try!(), ONCE_INIT, and Python security remediations generate safe patches."""
        rust_code = "let x = try!(do_work());\nstatic INIT: Once = std::sync::ONCE_INIT;\n"
        rs_findings = parry.scan_source(rust_code, "lib.rs", "rust")
        rs_fixed, rs_applied = parry.apply_fixes_to_source(rust_code, rs_findings)
        self.assertEqual(len(rs_applied), 2)
        self.assertIn("do_work()?", rs_fixed)
        self.assertIn("std::sync::Once::new()", rs_fixed)

        py_sec = "subprocess.run(cmd, shell=True)\nrequests.get(url, verify=False)\n"
        py_findings = parry.scan_source(py_sec, "run.py", "python")
        py_fixed, py_applied = parry.apply_fixes_to_source(py_sec, py_findings)
        self.assertEqual(len(py_applied), 2)
        self.assertIn("shell=False", py_fixed)
        self.assertNotIn("verify=False", py_fixed)

    def test_apply_fixes_to_source(self) -> None:
        """Verify apply_fixes_to_source modifies the source text and generates a clean diff."""
        source = (
            "export function setup() {\n"
            "  const buf = new Buffer(256);\n"
            "  const items = [10, 2, 30].sort();\n"
            "  return buf;\n"
            "}\n"
        )
        findings = parry.scan_source(source, "src/setup.ts", "typescript")
        fixed_source, applied = parry.apply_fixes_to_source(source, findings)

        self.assertEqual(len(applied), 2)
        self.assertIn("Buffer.alloc(256)", fixed_source)
        self.assertIn(".sort((a, b) => a - b)", fixed_source)
        self.assertNotIn("new Buffer", fixed_source)

        diff = parry.generate_unified_diff(source, fixed_source, "src/setup.ts")
        self.assertIn("-  const buf = new Buffer(256);", diff)
        self.assertIn("+  const buf = Buffer.alloc(256);", diff)

    def test_parry_fix_file_in_place_and_dry_run(self) -> None:
        """Verify parry fix --dry-run preserves file and parry fix repairs files on disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = pathlib.Path(tmpdir) / "app.ts"
            original = "const buf = new Buffer(128);\n"
            file_path.write_text(original, encoding="utf-8")

            # Dry run should NOT modify disk
            exit_dry = parry.main(["fix", "--dry-run", str(file_path)])
            self.assertEqual(exit_dry, 0)
            self.assertEqual(file_path.read_text(encoding="utf-8"), original)

            # Live fix modifies file in-place
            exit_code = parry.main(["fix", str(file_path)])
            self.assertEqual(exit_code, 0)
            updated = file_path.read_text(encoding="utf-8")
            self.assertEqual(updated, "const buf = Buffer.alloc(128);\n")

            # Second scan finds 0 issues
            remaining = parry.scan_file(file_path)
            self.assertEqual(len(remaining), 0)

    def test_check_format_json_includes_remediation(self) -> None:
        """Verify parry check --format json outputs prompt_injection_patch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = pathlib.Path(tmpdir) / "legacy.ts"
            file_path.write_text("import { useQuery } from 'react-query';\n", encoding="utf-8")

            stdout_buf = io.StringIO()
            with mock.patch("sys.stdout", stdout_buf):
                code = parry.main(["check", str(file_path), "--format", "json"])
            self.assertEqual(code, 1)

            parsed = json.loads(stdout_buf.getvalue())
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0]["rule_id"], "PARRY-HAL-TS003")
            self.assertIn("@tanstack/react-query", parsed[0]["suggested_replacement"])
            self.assertTrue(len(parsed[0]["prompt_injection_patch"]) > 10)

    def test_mcp_parry_fix_code_tool(self) -> None:
        """Verify MCP server handles parry_fix_code JSON-RPC requests."""
        req = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "parry_fix_code",
                "arguments": {
                    "language": "typescript",
                    "file_path": "utils.ts",
                    "code": "const s = text.substr(1, 3);\n",
                },
            },
        }
        fake_in = io.StringIO(json.dumps(req) + "\n")
        fake_out = io.StringIO()
        with mock.patch("sys.stdin", fake_in), mock.patch("sys.stdout", fake_out):
            parry.run_mcp_stdio_server()

        resp = json.loads(fake_out.getvalue().strip())
        self.assertEqual(resp["id"], 42)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(payload["fixed_count"], 1)
        self.assertIn(".slice(1, 3)", payload["patched_code"])
        self.assertIn("--- a/utils.ts", payload["unified_diff"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
