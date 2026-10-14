# Build guide

## Prerequisites

- A hypervisor (Hyper-V or Proxmox) and Windows Server / Windows client evaluation media acquired from Microsoft.
- An **internal/private virtual switch with no uplink**. Verify the switch does not bridge to a home, corporate, or campus network.
- At least 4 VMs: domain controller, event collector, domain endpoint, and separate admin workstation. Size each VM for the chosen Windows release.
- Snapshots before domain promotion and policy changes. Keep a hypervisor console open for recovery.
- Unique lab passwords kept in an approved local password manager. Never commit secrets or real host identifiers.

## 1. Create the network and VMs

Create an isolated IPv4 subnet such as `10.50.0.0/24`, without a default gateway. Use addresses from the README table. Set client and collector DNS to `10.50.0.10`. Do not configure NAT or internet routing for the lab. Snapshot clean VMs.

## 2. Create a new lab forest

On DC01, install the AD DS role and create a new forest, for example `lab.example.test`, using Server Manager or the documented AD DS deployment process. Use a unique Directory Services Restore Mode password. Verify DNS and domain controller health before joining other machines. Do not reuse a production forest or synchronize the lab to cloud identity.

Create separate OUs for `Servers`, `Workstations`, `Privileged Accounts`, and `Lab Users`. Create separate standard and administrative test accounts. Delegate only the minimum lab tasks needed; reserve domain-level administration for setup and recovery.

## 3. Establish an audit baseline

Use Group Policy Management to create a dedicated GPO linked to the test workstation OU. Configure Advanced Audit Policy for account logon, account management, logon/logoff, policy change, process creation, and directory service changes where appropriate. Enable command-line capture for process creation only after reviewing privacy and log volume. Verify Advanced Audit Policy does not conflict with legacy audit policy settings.

Apply changes only to lab VMs. Back up GPOs through Group Policy Management before editing. Record the GPO version and tested event IDs in `docs/evidence-template.md`.

## 4. Configure Windows Event Collection

On WEC01, enable Windows Event Collector service and configure the computer to receive subscriptions (for example, from an elevated PowerShell session using `wecutil qc` after reviewing Microsoft's WEF documentation). Configure the relevant WinRM listener and firewall settings through a narrowly scoped lab GPO. Create a **source-initiated** subscription for the chosen Security and Sysmon/Operational events; apply its client-side subscription policy to WIN11-01.

Check subscription runtime status in Event Viewer under **Subscriptions** and verify a benign event appears on WEC01. Do not assume event channels are enabled simply because the collector is configured; set channel and audit policy on the source first. Keep admin and collector access scoped to the lab.

## 5. Install and configure Sysmon

Obtain Sysmon from the official Microsoft Sysinternals page. Review `configs/sysmon/lab-sysmon.xml`, then install Sysmon on WIN11-01 using Microsoft's documented procedure. The sample config collects PowerShell process creation and network connections to keep the exercise manageable. Confirm the active config and inspect the Sysmon Operational log before tuning.

Sysmon writes telemetry; it does not label activity malicious or generate alerts. The collection and analysis stages are separate. Tune event volume and filters for the host workload.

## 6. Run benign test cases

From the lab endpoint, perform documented benign actions from `docs/validation.md`: an intentionally mistyped test-account login, adding a temporary lab user to a test admin group, and running a harmless PowerShell command that contains a test string in a comment. Revert temporary membership afterward. These tests exercise logging/detection logic; they do not simulate compromise.

Capture sanitized screenshots or short excerpts only after validating that events arrived at WEC01. Keep raw event logs and snapshots local. Never upload `.evtx` exports from a real system.

## Rollback

Remove temporary group membership, revert test GPO changes, and restore VM snapshots if needed. Delete test accounts and credentials. Keep the virtual switch isolated until all VMs are shut down. If the lab network ever had an unintended route, disconnect it and rebuild from clean snapshots before continuing.
