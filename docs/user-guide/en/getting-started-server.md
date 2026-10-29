---
id: getting-started-server
title: Getting started (server)
mode: server
order: 21
---

## Sign in {#sign-in}

Open the address of atlas-duck that your organisation gave you. The page "Sign in to atlas-duck" asks for your username and password. These are your organisation's directory credentials (a domain login). atlas-duck checks the password against the directory and never stores it.

| Message | What it means |
| --- | --- |
| Username or password is wrong. | The directory did not accept the credentials. |
| Too many attempts. Try again in N minutes. | There is a limit on failed sign-ins. Wait for the time shown. |
| The directory cannot be reached. Try again later. | The organisation's directory does not answer. |
| Your account is not permitted to use atlas-duck. | Your account is in none of the directory groups that atlas-duck accepts, or it is disabled. Ask your administrator. |
| Signing in failed. Try again. | Any other failure. |

After you sign in, your browser holds a session. A session is short-lived: it ends after a period without activity and after a maximum lifetime, both set by the people who run the server (by default 30 minutes idle and 8 hours in total). Then you sign in again. "Sign out" in the header ends it at once.

The header links to the pages you can use: Approvals, Credentials, API keys, Connected apps, My audit, and, if you have the role, Auditor and Admin. It also has the language choice and the Help entry.

## Store your tokens {#add-credentials}

atlas-duck acts towards Jira and Confluence as you, with your own personal access token for each instance. The instances themselves are set up by an admin. Open "Credentials" in the header:

1. If the page says "No instance is configured yet. An admin adds instances.", ask your admin first.
2. Choose "Add token" next to an instance, paste the token and choose "Check and save". atlas-duck tests the token against the instance before it stores it.
3. The row now shows "Token stored", with the Atlassian user it belongs to.

How to create the token, what the states mean and what the errors say is in [Instances and tokens](instances-and-tokens#credentials-page).

## Connect an agent {#connect-agent}

An agent reaches atlas-duck over MCP in one of two ways:

- With an **API key** that you create under "API keys". A key has scopes (read, propose_write, scripts), expires after 1 to 90 days and can be revoked. See [Agents (server)](agents-server#api-keys).
- Through **OAuth**, if your organisation enables it: an MCP client that supports it sends you to atlas-duck to allow it. You answer on the consent page and can revoke the app later under "Connected apps". See [Agents (server)](agents-server#oauth-consent).

Neither an API key nor a connected app can approve anything. You decide on the "Approvals" page: see [Approvals](approvals). To be alerted when something waits for you, choose "Enable notifications" there ([Settings](settings#notifications)).

## Roles {#roles}

What you may do depends on your role, and your roles come from your directory groups when you sign in.

| Role | What it may do |
| --- | --- |
| User | Everyone who can sign in. You own your tokens, approve your agents' writes and own your audit chain. |
| Auditor | Reads and exports every user's audit chain. Each such read is recorded in the auditor's own chain. See [Auditor](auditor). |
| Admin | Operates the deployment: instances, keys, backups. An admin has no access to users' tokens or audit contents. See [Administration](admin). |

The "Auditor" and "Admin" links appear in the header only if you hold the role. A person in none of the configured groups cannot sign in.
