# Validation plan

The GitHub workflow validates only the offline Python tool and synthetic fixture expectations. It does not run Windows, apply GPOs, install Sysmon, or validate a SIEM backend.

| Test | Expected evidence |
| --- | --- |
| Verify domain and DNS | `dcdiag /test:dns` and `Get-ADDomain` complete on DC01 |
| Verify GPO application | `gpresult /scope computer /r` on WIN11-01 shows the lab audit GPO |
| Verify audit events | A controlled failed sign-in produces Security event 4625 on the endpoint |
| Verify group audit | Adding/removing a test user in a lab group produces the applicable event (4728/4732/4756) |
| Verify Sysmon | A benign new process appears in Sysmon/Operational with process event ID 1 |
| Verify forwarding | WEC01 subscription runtime status is active and the test endpoint events appear centrally |
| Verify triage demo | `python tools/triage_events.py samples/events.jsonl` returns 3 findings |
| Verify regression tests | `python -m unittest discover -s tests -v` passes |

For each live Windows test, record OS/build, GPO name/version, test time, event ID, collector status, sanitized result, and cleanup in `docs/evidence-template.md`. A missing event can indicate audit policy, channel permissions, subscription filters, connectivity, clock, or log retention; troubleshoot those separately.
