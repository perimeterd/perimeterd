#!/usr/bin/env python3
"""Semantic boundaries for native shard evidence and bounded summaries."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/e2e-phases.py"
spec = importlib.util.spec_from_file_location("e2e_phases", SCRIPT)
phases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(phases)


def record(event, **fields):
    return {"event": event, "scenario": "TestNative/nftables", "backend": "nftables",
            "timestamp": "2026-11-05T01:00:00Z", **fields}


class PhaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def write_records(self, records):
        (self.directory / "phases-1.jsonl").write_text(
            "".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")

    def guard(self):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.directory), "--require-native"],
                              capture_output=True, text=True, check=False)

    def test_empty_and_helper_only_shards_fail(self):
        self.assertNotEqual(self.guard().returncode, 0)
        self.write_records([record("comparison", duration_ns=100)])
        self.assertNotEqual(self.guard().returncode, 0)

    def test_completed_native_work_passes(self):
        self.write_records([record("namespace_start"), record("capture", capture_commands=1,
                                                              capture_bytes=100, duration_ns=200),
                            record("measurement", phase="renewal", profile="small",
                                   source_decisions=1024, static_memberships=1024,
                                   projected_memberships=1024, duration_ns=100),
                            record("namespace_end", outcome="success", wall_ns=500)])
        self.assertEqual(self.guard().returncode, 0)

    def test_failure_timeout_unfinished_and_unmatched_namespaces_fail(self):
        cases = [
            [record("namespace_start")],
            [record("namespace_end", outcome="success")],
            [record("namespace_start"), record("namespace_end", outcome="failure")],
            [record("namespace_start"), record("namespace_end", outcome="timeout")],
            [record("namespace_start"), record("namespace_end", outcome="success", backend="other")],
            [record("namespace_start"), record("namespace_start"),
             record("namespace_end", outcome="success")],
            [record("namespace_start"), record("namespace_end", outcome="success"),
             record("namespace_start", scenario="TestUnfinished")],
        ]
        for records in cases:
            with self.subTest(records=records):
                self.write_records(records)
                self.assertNotEqual(self.guard().returncode, 0)

    def test_all_completed_namespaces_are_required(self):
        records = []
        for backend in ("nftables", "iptables-legacy", "iptables-nft"):
            records.extend([record("namespace_start", backend=backend),
                            record("namespace_end", backend=backend, outcome="success")])
        self.write_records(records)
        self.assertEqual(self.guard().returncode, 0)
        records[-1]["outcome"] = "failure"
        self.write_records(records)
        self.assertNotEqual(self.guard().returncode, 0)

    def test_malformed_and_incomplete_records_fail_closed(self):
        for raw in (b"not JSON\n", b"{}\n", b"[]\n", b"\xff\n", b"{}",
                    b" " * (phases.MAX_LINE + 1) + b"\n"):
            with self.subTest(raw=raw[:20]):
                (self.directory / "phases-1.jsonl").write_bytes(raw)
                self.assertNotEqual(self.guard().returncode, 0)

    def test_fixed_schema_and_numeric_boundaries(self):
        cases = [record("capture", native_payload="SECRET"),
                 record("capture", capture_bytes=True), record("capture", capture_bytes=-1),
                 record("capture", capture_bytes=1 << 63), record("capture", capture_bytes=1.5),
                 record("measurement", source_decisions=-1),
                 record("capture", timestamp="2026-11-05T01:00:00"),
                 record("capture", scenario="bad\nlabel"), record("capture", scenario="x" * 257)]
        for item in cases:
            with self.subTest(item=item):
                self.write_records([item])
                result = self.guard()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("SECRET", result.stdout + result.stderr)

    def test_record_and_byte_budgets_fail_closed(self):
        self.write_records([record("capture"), record("capture")])
        with patch.object(phases, "MAX_RECORDS", 1):
            with self.assertRaises(phases.PhaseError):
                phases.load_records(self.directory)
        with patch.object(phases, "MAX_BYTES", 1):
            with self.assertRaises(phases.PhaseError):
                phases.load_records(self.directory)

    def test_symlink_is_not_phase_evidence(self):
        target = self.directory / "outside"
        target.write_text(json.dumps(record("namespace_start")) + "\n", encoding="utf-8")
        (self.directory / "phases-1.jsonl").symlink_to(target)
        self.assertNotEqual(self.guard().returncode, 0)

    def test_summary_totals_slowest_and_wall_inputs(self):
        records = [record("namespace_start"),
                   record("capture", phase="inspect", profile="production", duration_ns=3_000_000_000,
                          capture_commands=2, capture_bytes=123),
                   record("comparison", phase="exact", duration_ns=1_000_000_000),
                   record("namespace_end", outcome="success", wall_ns=6_000_000_000,
                          timestamp="2026-11-05T01:00:06Z")]
        summary = phases.summarize(records, "2026-11-05T01:00:00Z",
                                   datetime(2026, 11, 5, 1, 0, 12, tzinfo=timezone.utc))
        self.assertEqual(summary["totals"]["capture_commands"], 2)
        self.assertEqual(summary["totals"]["capture_bytes"], 123)
        self.assertEqual(summary["totals"]["duration_ns"], 4_000_000_000)
        self.assertEqual(summary["slowest_phases"][0]["phase"], "inspect")
        self.assertEqual(summary["namespace_wall_ns"], 6_000_000_000)
        self.assertEqual(summary["native_span_seconds"], 6)
        self.assertEqual(summary["shard_wall_seconds"], 12)
        self.assertAlmostEqual(summary["runner_minutes"], 0.2)
        self.assertIn("not shard wall time", phases.markdown(summary))

    def test_phase_wall_ranks_without_counting_namespace_as_a_phase(self):
        records = [record("namespace_start"),
                   record("capture", phase="inspect", duration_ns=3_000_000_000),
                   record("phase_end", phase="startup", wall_ns=8_000_000_000),
                   record("namespace_end", outcome="success", wall_ns=60_000_000_000)]
        summary = phases.summarize(records)
        self.assertEqual(summary["slowest_phases"][0]["phase"], "startup")
        self.assertEqual(summary["slowest_phases"][0]["duration_ns"], 8_000_000_000)
        self.assertNotIn("namespace_end", [row["event"] for row in summary["slowest_phases"]])

    def test_cli_summary_is_small_and_contains_no_raw_records(self):
        self.write_records([record("namespace_start"), record("namespace_end", outcome="success")])
        output = self.directory / "summary.json"
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.directory),
                                 "--require-native", "--summary", str(output)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(summary["records"], 2)
        self.assertNotIn("timestamp", summary)
        self.assertLess(output.stat().st_size, 8192)


if __name__ == "__main__":
    unittest.main()
