# Detection catalog

Rules under `rules/windows/` follow the Sigma rule format and are illustrative starting points. Review event field mappings and log collection with your intended backend. The offline Python tool uses normalized synthetic JSON, not Sigma conversion, and does not execute rule YAML.

| Detection | Source event | Lab test | Tuning notes |
| --- | --- | --- | --- |
| Repeated failed logons | Security 4625 | Mistype test account password 5 times within 5 minutes | Baseline service accounts and expected lockout tests; threshold is lab-only |
| Security group membership change | Security 4728, 4732, 4756 | Add and remove a temporary test account from a lab admin group | Check whether the affected group is privileged; distinguish approved changes and validate event semantics |
| Suspicious PowerShell indicators | PowerShell 4104 | Run a harmless comment containing the literal test marker `Invoke-Expression` | String matching can be noisy; script block logging must be enabled and field names checked |

## Microsoft Sentinel query examples

- [Windows failed-logon burst](../queries/sentinel/failed-logon-burst.kql) groups Security event 4625 records by source IP and fixed five-minute bins.
- [Entra ID failed interactive sign-ins](../queries/sentinel/entra-failed-signins.kql) groups failed sign-ins by user and IP, and collapses records sharing a correlation ID to the latest result.

Both queries are analyst starting points, not production detections. Fixed bins can split activity that crosses a boundary. Validate the table schema and query behavior in the intended workspace. Neither query has been run against a live Sentinel workspace, and CI does not execute KQL.

See the [synthetic failed-logon investigation](case-studies/failed-logon-burst.md) for an end-to-end triage walkthrough and the [Entra sign-in review](case-studies/entra-sign-in-review.md) for a cloud identity investigation checklist.

Every rule should document required telemetry, a plausible false positive, and an exact validation method. The examples intentionally avoid downloading payloads, credential access, persistence, evasion, or execution of harmful commands.
