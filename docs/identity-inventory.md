# Read-only identity inventory

`scripts/Get-LabIdentityPosture.ps1` collects basic forest/domain metadata, the default domain password and lockout policy, domain controller inventory, and recursive membership for the Domain Admins, Enterprise Admins, and Schema Admins groups. It writes JSON locally and makes no directory or policy changes.

Run in an elevated PowerShell session with the ActiveDirectory module and read permissions for the connected lab domain:

```powershell
.\scripts\Get-LabIdentityPosture.ps1 -OutputPath .\reports\identity-posture.json
```

Create the `reports` directory first. Review the resulting report before sharing it; domain names, hostnames, and account names can be sensitive. The script queries the current domain and its forest root. It does not enumerate every domain in a multi-domain forest, evaluate effective GPO settings, assess nested local groups, or make a compliance determination. Validate behavior in the isolated lab and keep real organization output private.
