# Lab triage workflow

1. Preserve the relevant event records and note the collection host, time range, source, and event IDs.
2. Check whether the activity is expected lab work: identify the test account, change owner, approved group, and test schedule.
3. Correlate endpoint, domain controller, and collector events. Verify timestamps and whether collection gaps exist before interpreting an absence of events.
4. For real incidents, follow the organization's incident response process, preserve evidence, and escalate through approved channels. This lab's rules do not establish malicious intent.
5. Remove temporary group membership, rotate lab credentials if exposed, and restore snapshots as appropriate.
6. Record the outcome, false positives, and needed rule tuning without including production data in the public repository.
