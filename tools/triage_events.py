"""Triage a small normalized JSONL set of synthetic Windows security events."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import sys

GROUP_CHANGE_IDS = {4728, 4732, 4756}
FAILED_LOGON_ID = 4625
POWERSHELL_SCRIPT_BLOCK_ID = 4104
BURST_COUNT = 5
WINDOW_SECONDS = 5 * 60
REVIEW_INDICATOR = "invoke-expression"


def parse_time(value, line_number):
    if not isinstance(value, str) or not value:
        raise ValueError(f"line {line_number}: timestamp must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"line {line_number}: invalid ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"line {line_number}: timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def load_events(text):
    events = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {number}: malformed JSON") from exc
        if not isinstance(event, dict):
            raise ValueError(f"line {number}: event must be a JSON object")
        event_id = event.get("event_id")
        if isinstance(event_id, bool) or not isinstance(event_id, int) or not 0 <= event_id <= 65535:
            raise ValueError(f"line {number}: event_id must be an integer between 0 and 65535")
        record = dict(event)
        record["_line"] = number
        if "timestamp" in record:
            record["_time"] = parse_time(record["timestamp"], number)
        if "source_ip" in record and record["source_ip"]:
            try:
                record["source_ip"] = str(ipaddress.ip_address(record["source_ip"]))
            except ValueError as exc:
                raise ValueError(f"line {number}: invalid source_ip") from exc
        for field in ("computer", "channel", "source_ip", "target_user", "group", "script_block_text"):
            if field in record and not isinstance(record[field], str):
                raise ValueError(f"line {number}: {field} must be a string")
        events.append(record)
    if not events:
        raise ValueError("no events found")
    return events


def detect(text):
    events = load_events(text)
    findings = []
    failed_by_source = defaultdict(list)

    for event in events:
        event_id = event["event_id"]
        if event_id == FAILED_LOGON_ID and event.get("source_ip") and "_time" in event:
            failed_by_source[event["source_ip"]].append(event)
        if event_id in GROUP_CHANGE_IDS and event.get("group"):
            findings.append({
                "rule": "SECURITY_GROUP_MEMBERSHIP_CHANGE",
                "severity": "medium",
                "line": event["_line"],
                "event_id": event_id,
                "computer": event.get("computer"),
                "group": event["group"],
                "target_user": event.get("target_user"),
                "review": "Confirm whether this group is privileged and whether the change was approved.",
            })
        if event_id == POWERSHELL_SCRIPT_BLOCK_ID and REVIEW_INDICATOR in event.get("script_block_text", "").casefold():
            findings.append({
                "rule": "POWERSHELL_SCRIPT_BLOCK_REVIEW",
                "severity": "medium",
                "line": event["_line"],
                "event_id": event_id,
                "computer": event.get("computer"),
                "review": "Review the script block and its context; a string match alone is not a verdict.",
            })

    for source, source_events in sorted(failed_by_source.items()):
        ordered = sorted(source_events, key=lambda item: (item["_time"], item["_line"]))
        left = 0
        for right, event in enumerate(ordered):
            while (event["_time"] - ordered[left]["_time"]).total_seconds() > WINDOW_SECONDS:
                left += 1
            window = ordered[left:right + 1]
            if len(window) >= BURST_COUNT:
                findings.append({
                    "rule": "FAILED_LOGON_BURST",
                    "severity": "low",
                    "source_ip": source,
                    "first_line": window[0]["_line"],
                    "last_line": event["_line"],
                    "event_count": len(window),
                    "target_users": sorted({item.get("target_user", "") for item in window if item.get("target_user")}),
                    "review": "Check expected testing, user mistakes, and source ownership before escalation.",
                })
                break
    return {"events_parsed": len(events), "findings": findings,
            "scope": "synthetic normalized JSONL; findings require analyst review"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="newline-delimited normalized JSON event records")
    args = parser.parse_args(argv)
    try:
        result = detect(args.events.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
