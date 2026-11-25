# Validation plan

The GitHub workflow parses the three Sigma YAML files and Sysmon XML, runs the offline Python tests, and checks the synthetic triage fixture. It does not provision Windows, run a domain, collect events, or execute KQL in Microsoft Sentinel.

| Test | Expected evidence |
| --- | --- |
| Verify domain and DNS | `dcdiag /test:dns` and `Get-ADDomain` complete on DC01 |
| Verify GPO application | `gpresult /scope computer /r` on WIN11-01 shows the lab audit GPO |
| Verify audit events | A controlled failed sign-in produces Security event 4625 on the endpoint |
| Verify group audit | Adding/removing a test user in a lab group produces the applicable event (4728/4732/4756) |
| Verify Sysmon | A benign new process appears in Sysmon/Operational with process event ID 1 |
| Verify forwarding | WEC01 subscription runtime status is active and the test endpoint events appear centrally |
| Verify offline triage | `python tools/triage_events.py samples/events.jsonl` returns 3 findings |
| Verify regression tests | `python -m unittest discover -s tests -v` passes |
| Validate Sentinel queries | Run each query in `queries/sentinel/` against a workspace with the corresponding table; compare results with controlled, benign test events and record schema/connector details |

For each live Windows test, record OS/build, GPO name/version, test time, event ID, collector status, sanitized result, and cleanup in [the evidence template](evidence-template.md). For a Sentinel test, record workspace table/connector, query revision, time range, expected versus observed result, and sanitized output.

A missing event can indicate audit policy, channel permissions, subscription filters, connectivity, clock, or log retention; troubleshoot those separately. Do not mark a Sentinel query as validated until it has run against the target workspace. Never place tenant identifiers, real user data, or employer logs in public evidence.
