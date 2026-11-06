#!/usr/bin/env python3
"""Summarize bounded native phase records and reject vacuous native shards."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys

STRING_FIELDS = {
    "backend", "scenario", "profile", "phase", "event", "outcome",
    "static_generation", "dynamic_generation", "resource", "capacity_scope",
}
NUMBER_FIELDS = {
    "static_memberships", "source_decisions", "projected_memberships", "static_generations",
    "dynamic_generations", "capture_commands", "capture_bytes", "duration_ns",
    "wall_ns", "child_user_ns", "child_system_ns", "child_max_rss_kib",
    "daemon_max_rss_kib", "required_bytes", "limit_bytes",
}
MAX_LINE = 4096
MAX_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 16384
SAFE_TEXT = re.compile(r"[A-Za-z0-9_./:+=@ ()\[\],-]{0,256}", re.ASCII)


class PhaseError(ValueError):
    """The phase evidence is absent, malformed or incomplete."""


def timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        raise PhaseError("invalid phase timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PhaseError("invalid phase timestamp") from None
    if result.tzinfo is None:
        raise PhaseError("phase timestamp requires timezone")
    return result


def validate(record):
    if not isinstance(record, dict) or set(record) - (STRING_FIELDS | NUMBER_FIELDS | {"timestamp"}):
        raise PhaseError("phase record has unknown fields")
    for field in STRING_FIELDS:
        value = record.get(field, "")
        if not isinstance(value, str) or not SAFE_TEXT.fullmatch(value):
            raise PhaseError("invalid phase label")
    for field in NUMBER_FIELDS & record.keys():
        value = record[field]
        if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
            raise PhaseError("invalid phase measurement")
    if not record.get("event") or not record.get("scenario"):
        raise PhaseError("phase event and scenario required")
    timestamp(record.get("timestamp"))
    return record


def load_records(directory):
    records = []
    size = 0
    for path in sorted(Path(directory).glob("*.jsonl")):
        if path.is_symlink() or not path.is_file():
            raise PhaseError("phase input must be a regular file")
        with path.open("rb") as stream:
            while True:
                line = stream.readline(MAX_LINE + 1)
                if not line:
                    break
                size += len(line)
                if len(line) > MAX_LINE or size > MAX_BYTES or len(records) >= MAX_RECORDS:
                    raise PhaseError("phase evidence exceeds bounded record limits")
                if not line.endswith(b"\n"):
                    raise PhaseError("incomplete phase record")
                try:
                    record = json.loads(line)
                except (ValueError, UnicodeError):
                    raise PhaseError("invalid phase JSON") from None
                records.append(validate(record))
    return records


def require_native(records):
    active = Counter()
    completed = 0
    for record in records:
        key = (record["scenario"], record.get("backend", ""))
        if record["event"] == "namespace_start":
            active[key] += 1
        elif record["event"] == "namespace_end":
            if not active[key] or record.get("outcome") != "success":
                raise PhaseError("native namespace did not complete successfully")
            active[key] -= 1
            completed += 1
    if not completed or any(active.values()):
        raise PhaseError("intended native shard has no complete native work or unfinished namespaces")


def summarize(records, started_at=None, ended_at=None):
    totals = {field: sum(record.get(field, 0) for record in records)
              for field in ("duration_ns", "wall_ns", "capture_commands", "capture_bytes",
                            "child_user_ns", "child_system_ns")}
    phases = Counter()
    for record in records:
        key = (record.get("backend", ""), record["scenario"], record.get("profile", ""),
               record.get("phase", ""), record["event"])
        if record["event"] != "namespace_end":
            duration = record.get("wall_ns", 0) if record["event"] == "phase_end" else record.get("duration_ns", 0)
            phases[key] += duration
    slowest = [dict(zip(("backend", "scenario", "profile", "phase", "event"), key),
                    duration_ns=duration)
               for key, duration in phases.most_common(10)]
    starts = [timestamp(record["timestamp"]) for record in records
              if record["event"] == "namespace_start"]
    ends = [timestamp(record["timestamp"]) for record in records
            if record["event"] == "namespace_end"]
    namespace_wall_ns = sum(record.get("wall_ns", 0) for record in records
                            if record["event"] == "namespace_end")
    result = {"records": len(records), "totals": totals, "slowest_phases": slowest,
              "namespace_wall_ns": namespace_wall_ns}
    if starts and ends:
        result["native_span_seconds"] = max(0, (max(ends) - min(starts)).total_seconds())
    if started_at:
        elapsed = ((ended_at or datetime.now(timezone.utc)) - timestamp(started_at)).total_seconds()
        if elapsed < 0:
            raise PhaseError("shard wall start is in the future")
        result["shard_wall_seconds"] = elapsed
        result["runner_minutes"] = elapsed / 60
    return result


def markdown(summary):
    lines = ["### Native E2E phase summary", "",
             "Recorded phase times may overlap; they are not shard wall time.", "",
             f"Records: {summary['records']}; capture commands: {summary['totals']['capture_commands']}; "
             f"capture bytes: {summary['totals']['capture_bytes']}; "
             f"recorded duration: {summary['totals']['duration_ns'] / 1e9:.3f}s."]
    if "shard_wall_seconds" in summary:
        lines.append(f"Shard wall: {summary['shard_wall_seconds']:.3f}s; "
                     f"runner minutes: {summary['runner_minutes']:.3f}. "
                     "Sum runner minutes and take the maximum shard wall across shards for cost/critical-path inputs "
                     "(queue and setup time excluded).")
    lines.extend(["", "| Backend | Scenario | Profile | Phase / event | Recorded seconds |",
                  "| --- | --- | --- | --- | ---: |"])
    for row in summary["slowest_phases"]:
        lines.append(f"| {row['backend']} | {row['scenario']} | {row['profile']} | "
                     f"{row['phase']} / {row['event']} | {row['duration_ns'] / 1e9:.3f} |")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--require-native", action="store_true")
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--started-at")
    args = parser.parse_args(argv)
    try:
        records = load_records(args.directory)
        if args.require_native:
            require_native(records)
        if args.summary:
            summary = summarize(records, args.started_at)
            args.summary.parent.mkdir(parents=True, exist_ok=True)
            args.summary.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
            text = markdown(summary)
            print(text, end="")
            if os.environ.get("GITHUB_STEP_SUMMARY"):
                with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
                    stream.write(text)
    except (OSError, PhaseError) as error:
        print(f"native phase evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
