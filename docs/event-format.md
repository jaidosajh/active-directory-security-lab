# Normalized event format

`tools/triage_events.py` accepts newline-delimited UTF-8 JSON. Each record is an event normalized by an analyst or a trusted export process into this schema:

```json
{"timestamp":"2026-01-15T12:00:00Z","event_id":4625,"computer":"WIN11-01.lab.example.test","channel":"Security","source_ip":"10.50.0.31","target_user":"lab-user","group":"","script_block_text":""}
```

Required field: integer `event_id`. Optional fields: ISO 8601 `timestamp`, string `computer`, `channel`, `source_ip`, `target_user`, `group`, and `script_block_text`. Unknown fields are ignored. The fixture values are synthetic. The parser rejects malformed JSON, missing/invalid event IDs, and invalid timestamps; it does not ingest EVTX files, authenticate to Windows, or export provider-specific XML automatically.

Detection behavior:

- 4625 failures are grouped by source IP. Five or more events inside any five-minute window trigger a review finding. Events without source IP are ignored by this correlation.
- 4728, 4732, or 4756 triggers a security group membership review only when a group name is supplied. Determine separately whether that group is privileged.
- 4104 triggers a PowerShell review when the script block contains the literal indicator `invoke-expression` (case-insensitive).

These are triage signals for the exercise, not threat conclusions. Results include source records' line numbers for evidence traceability within the input file.
