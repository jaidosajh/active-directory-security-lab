# Detection catalog

Rules under `rules/windows/` follow the Sigma rule format and are illustrative starting points. Review event field mappings and log collection with your intended backend. The offline Python tool uses normalized synthetic JSON, not Sigma conversion, and does not execute rule YAML.

| Detection | Source event | Lab test | Tuning notes |
| --- | --- | --- | --- |
| Repeated failed logons | Security 4625 | Mistype test account password 5 times within 5 minutes | Baseline service accounts and expected lockout tests; threshold is lab-only |
| Security group membership change | Security 4728, 4732, 4756 | Add and remove a temporary test account from a lab admin group | Check whether the affected group is privileged; distinguish approved changes and validate event semantics |
| Suspicious PowerShell indicators | PowerShell 4104 | Run a harmless comment containing the literal test marker `Invoke-Expression` | String matching can be noisy; script block logging must be enabled and field names checked |

Every rule should document required telemetry, a plausible false positive, and an exact validation method. The examples intentionally avoid downloading payloads, credential access, persistence, evasion, or execution of harmful commands.
