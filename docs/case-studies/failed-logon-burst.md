# Case study: failed-logon burst investigation

**Data status:** Synthetic offline walkthrough. The fixture is not a Windows event export, no real identity data is used, and the Sentinel query has not been run against a live workspace.

## Alert summary

The offline analyzer reports a low-severity `FAILED_LOGON_BURST` finding for five synthetic Security event 4625 records from `10.50.0.31` in a five-minute period. The records target `lab-user` on `WIN11-01.lab.example.test`.

Source: [synthetic event fixture](../../samples/events.jsonl). Reproduce with:

```bash
python tools/triage_events.py samples/events.jsonl
python -m unittest discover -s tests -v
```

The fixture also includes a synthetic event 4624 for the same account and source at 12:05 UTC. Treat it as a lead to investigate. The offline rule does not correlate success events with failures or decide whether the activity was malicious.

## Timeline from the fixture

| UTC time | Synthetic evidence | Analyst interpretation |
| --- | --- | --- |
| 12:00:00–12:02:40 | Five event 4625 records from `10.50.0.31` for `lab-user` | Meets the lab threshold; could reflect a planned mistype test or unexpected activity |
| 12:05:00 | Event 4624 from the same source for `lab-user` | Review the logon type, workstation, domain controller, and surrounding events; a success after failures alone does not prove compromise |

## Investigation steps

1. Confirm whether a password-mistype or lockout test was scheduled during this window.
2. Identify the source device and confirm whether `10.50.0.31` was assigned to the lab endpoint at that time.
3. Review the raw Security event fields, especially logon type, status/substatus, workstation, target account, and timestamp.
4. Correlate the endpoint, domain controller, and Windows Event Collector records. Check clock alignment and collection gaps.
5. If the activity was unexpected, follow the organization's incident response process and preserve relevant evidence before taking account or host actions.

## Assessment and disposition

For this fixture, the appropriate disposition is **needs context; no confirmed incident**. The event pattern supports a review, not an attacker attribution. A possible mapping for a password-guessing analytic is [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/), but this synthetic pattern by itself does not establish that behavior.

Do not automatically block the source or disable the account based on this threshold. In a real environment, consider source ownership, the failure reason, account criticality, successful authentication, approved testing, and other correlated signals.

## Sentinel query

[Run the Sentinel KQL example](../../queries/sentinel/failed-logon-burst.kql) only in a workspace where the `SecurityEvent` table is populated. It uses fixed five-minute bins; a burst crossing a bin boundary can be split. The query is an example and has not been validated in a live Sentinel workspace.

## Evidence boundary

This report is generated from the repository's synthetic JSONL fixture. It does not demonstrate live Windows collection, Sigma execution, Sentinel query results, or a real security incident. Use [the evidence template](../evidence-template.md) to document actual, sanitized lab results after running them.
