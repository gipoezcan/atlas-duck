---
id: auditor
title: Auditor
mode: server
order: 100
---

## The auditor role {#auditor-role}

An auditor can read the audit log of any user, so that the organisation can check what agents did and who decided. The role comes from a directory group, see [Users and roles](admin#users-and-roles). Users without it do not see the page, and the server refuses the requests with "Auditors only."

The role gives read and export access to audit logs, nothing more. Nobody can change a log through these pages. Admins do not get this access: the roles are separate.

Auditing is itself audited. Every time an auditor lists users, opens a record, a trail or a payload, or starts or downloads an export, atlas-duck writes a record about it in the auditor's own log and in the server's anchor chain: which action, and whose log. If this record cannot be written, the server refuses the request and returns nothing. The page therefore says: "Every view is recorded in your own audit chain." Reading does not touch the log of the person you read. An export does record an export in that person's log.

The audit log holds personal data: names, comments, and the content that agents read. Read only what your task requires, and handle exports as personal data.

## Read the audit log {#reading-the-audit}

Open "Auditor" in the header. The page "Users" lists every user, including deactivated ones. "Search by username" finds a person, and "State" narrows the list to "Active" or "Deactivated" ("All" shows everybody). A deactivated user's log stays readable until the retention period has ended, see [Retention and legal hold](audit#retention).

Choose a user to open their log. The banner reminds you: "You are viewing NAME's audit chain. Every view is recorded in your own audit chain." The view is the same as in "My audit": filters, the list of records, the trail of a request and the decrypted payloads. How to read it is described in [What the audit log records](audit#audit-log). "Back to the users" returns to the list.

## Exports {#auditor-exports}

An auditor can export any user's log as a tar archive, for example for the compliance owner. In the user's view, choose "All records" or "From date (UTC)" and then "Start export". When "The export is ready" appears, use "Download". The file is available for a limited time (24 hours by default) and the page says that it can be downloaded once. Only the auditor who started an export can see and download it, and only while they still hold the role.

The page shows what the recipient needs to verify the export: the "Manifest SHA-256" and the "Anchor head". Use "Copy" to copy them. "Give the recipient the manifest SHA-256 and the anchor head by another channel than the archive." Without them the recipient cannot be sure that the archive is the real one.

The recipient verifies the archive offline with the command shown under "Verify with". The steps and the exit codes are in [Check an export with verify-export](audit#verify-export). Note that the archive contains decrypted payloads and an excerpt of the anchor chain; the excerpt shows the fingerprints of other users' log heads and how many users were anchored, but no names and no content.
