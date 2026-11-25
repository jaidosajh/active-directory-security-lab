# Case study: Entra ID failed sign-in review

**Data status:** Query walkthrough only. This repository contains no Entra tenant data and no live Sentinel result.

## Analytic question

Are there five or more failed interactive sign-in attempts for the same user from one IP address within a fixed 15-minute bin?

The [Sentinel KQL example](../../queries/sentinel/entra-failed-signins.kql) queries `SigninLogs`, keeps the latest result for records sharing a correlation ID, and summarizes by user, IP, and time bin. Microsoft documents that a single sign-in flow can produce multiple Log Analytics records, so check correlation IDs and final statuses before interpreting counts.

## Analyst review

For any returned row:

1. Review the user, application, error codes, first and last timestamps, and source IP.
2. Compare location and network ownership with the user's expected travel, VPN, and corporate egress.
3. Review device details, Conditional Access status, risk fields, and surrounding successful sign-ins.
4. Check related records by `CorrelationId`; distinguish interactive from non-interactive activity.
5. Confirm whether password resets, user reports, approved testing, or application changes explain the pattern.
6. Follow the organization's identity incident process. Do not block an IP or disable an account based on this query alone.

## Limitations

The query uses a fixed 15-minute bin and a threshold intended only as a starting point. It excludes non-interactive sign-ins and depends on `SigninLogs` availability and field population in the workspace. Validate the query and thresholds against a controlled test tenant before using it operationally. No tenant data, alert, or investigation outcome is claimed here.

For measured tenant or lab evidence, use [the validation evidence template](../evidence-template.md), sanitize identifiers, and record the query version and time range.
