# atlas-duck

atlas-duck lets AI agents read Jira and Confluence Data Center and propose writes that a human approves, with every action recorded in a tamper-evident audit chain.

## Language

**Desktop mode**:
atlas-duck installed and running on one user's own machine, serving that user and the agents running on that machine.
_Avoid_: local install, client

**Server mode**:
atlas-duck hosted once by the organisation, on its own network, serving many users and their agents with nothing installed on the user's machine.
_Avoid_: SaaS, cloud mode

**Organisation**:
The single company that operates a server-mode deployment and owns its identity provider; server mode serves exactly one.
_Avoid_: tenant, customer

**User**:
A person who owns personal access tokens, approves writes and owns an audit chain; in server mode identified by the organisation's identity provider.
_Avoid_: account, operator

**Agent**:
An AI program acting on a user's behalf through atlas-duck; it proposes writes but never approves them.
_Avoid_: client, bot

**Instance**:
One Jira or Confluence Data Center server that atlas-duck talks to, known by an alias.
_Avoid_: site, server (ambiguous with server mode)

**Personal access token (PAT)**:
A user's own Jira or Confluence token; atlas-duck always acts as that user, never as a shared service account.
_Avoid_: credential (too broad), service account

**Approval**:
A user's explicit yes or no to one proposed write before it reaches an instance; required for every write in both modes.
_Avoid_: confirmation, consent

**Domain login**:
Server-mode sign-in where the user types their organisation directory username and password, checked against the directory and never stored.
_Avoid_: SSO, AD login

**Role**:
What a signed-in user may do in server mode, granted by directory group membership: user, auditor or admin.
_Avoid_: permission, rights

**Auditor**:
A role that may read and export every user's audit chain; each such read is itself recorded in the auditor's own chain.
_Avoid_: admin (admins get no audit read access)

**Admin**:
A role that operates a server-mode deployment (instances, keys, backups) without access to users' tokens or audit contents.
_Avoid_: superuser, operator

**Session**:
A signed-in browser's short-lived proof of a domain login, used by the web UI.
_Avoid_: token (reserved for PATs and API keys)

**API key**:
A user-created, scoped, expiring, revocable secret that lets an agent act for that user in server mode without a browser sign-in.
_Avoid_: token, PAT

**Audit chain**:
One user's tamper-evident hash chain of everything atlas-duck did for them; one per user in both modes.
_Avoid_: log, history

**Server anchor chain**:
The server-mode chain that periodically records every user's audit-chain head, so later rewriting by whoever runs the server is detectable.
_Avoid_: anchor directory (desktop mode only), global log

**Master key**:
The single server-mode secret that encrypts each user's own data key; held outside the image and outside CI variables.
_Avoid_: password, secret (too broad)

**User guide**:
The end-user documentation for users, admins and auditors, in English and German, shipped with the desktop app and served by the server; opened from the "Help" entry.
_Avoid_: docs, documentation (too broad: the operations docs are separate), manual

**UI language**:
The language (English or German) a user's windows and web pages, notifications and native dialogs are shown in; agent-facing text, audit records, logs, the CLI and the operations docs stay English.
_Avoid_: locale (that is the OS or browser setting the choice may follow), translation

**Language preference**:
A user's choice of **UI language**: Automatic (German when the OS or browser language is German, else English), Deutsch or English; per user in **Server mode**, an app setting in **Desktop mode**; not audited.
_Avoid_: language setting (ambiguous with the OS locale)

**Operations docs**:
The documentation for the people who deploy and run the server; kept in the repository, never shipped to users.
_Avoid_: admin docs (an **Admin** is a user role, not an operator)

## Relationships

- An **Organisation** runs at most one **Server mode** deployment; **Desktop mode** and **Server mode** are built from the same codebase.
- A **User** owns zero or more **PATs**, one per **Instance** they use.
- In **Server mode** an **Admin** defines the **Instances** for everyone; users only add their **PATs**. In **Desktop mode** each **User** defines their own.
- A deactivated **User** loses their **PATs** at once; their **Audit chain** stays readable by **Auditors** for the retention period.
- An **Agent** acts for exactly one **User**; each write it proposes needs that **User**'s **Approval**.

- An **Agent** reaches **Server mode** through remote MCP (signed in by its **User**) or an **API key**.
- Every **User** has one **Audit chain**; the **Server anchor chain** records all chain heads.
- A **User** holds one or more **Roles** (auditor and admin come on top of user); each **Role** comes from a directory group at **Domain login**.

## Flagged ambiguities

- "server" meant both a Jira/Confluence host and the atlas-duck deployment: resolved as **Instance** and **Server mode**.
