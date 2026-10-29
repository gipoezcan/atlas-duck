---
id: admin
title: Administration
mode: server
order: 90
---

## Users and roles {#users-and-roles}

The server has three roles: user, admin and auditor. atlas-duck does not keep passwords or a list of roles of its own. A person signs in with their directory account, and the groups of that account decide the role. Your operator has linked one directory group to each role (`GROUP_USERS`, `GROUP_ADMINS`, `GROUP_AUDITORS`). To give or take a role, change the group membership in the directory. A person who is in none of the groups cannot sign in.

| Role | Can |
| --- | --- |
| User | Use the approval queue, store their own tokens, create API keys and read their own audit log. |
| Admin | Everything a user can, and manage the instances on the "Admin" page. |
| Auditor | Read the audit log of any user, see [The auditor role](auditor#auditor-role). |

Admins have no access to other users' audit logs. An admin also does not see anyone's stored token; nobody does, because atlas-duck never shows a stored token.

**Deactivating a user.** When someone leaves the organisation, the operator deactivates the account with `admin users deactivate <username>`. There is no button for this on the web pages. Deactivating is final and does the following at once: the person's sessions end, their API keys and OAuth grants are revoked, and their stored tokens are deleted. Each of these steps is recorded in the person's audit log. A deactivated person cannot sign in again, even if the directory still lists them. `admin users list` shows every user with roles, last login and state: active, deactivated or deleted.

Whether the server notices departed users by itself depends on how your operator set it up. Without a read-only directory account, the server refuses a disabled account only at its next login, and until then the person's API keys keep working. Deactivating by hand on the day someone leaves is then an operator duty. Ask your operator which case applies to you.

## Manage instances {#instances-admin}

As an admin you define the Jira and Confluence instances for everybody. Open "Admin" in the header. The page "Instances" says: "Every user sees these instances and enters their own token for each." Users do not add instances themselves, see [Instances and tokens](instances-and-tokens).

The table lists each instance with URL, Proxy, "Org CA" and "Default". To add one, fill in "Add an instance":

| Field | Meaning |
| --- | --- |
| Alias | The short name that users and agents use. Letters, digits, `-` and `_`. |
| Product | Jira or Confluence. |
| Base URL | The address of the server. It must start with `https://`. |
| Proxy (optional: direct, system or a proxy URL) | How atlas-duck reaches the server. |
| Use the organisation CA bundle | Check the server certificate against the organisation's certificate authority, which your operator has installed. Use this for servers with an internal certificate. |
| Default instance for this product | Marks the default instance of its product. A product can have only one default. |

Choose "Add instance". The messages tell you what is wrong: the alias exists already, the instance is not valid, or the change failed.

"Remove" removes an instance for everybody. atlas-duck asks first: "Remove the instance ALIAS? Every user's token for this instance will be deleted." Each user must then store a new token if the instance comes back. Removing is recorded in the audit log of each affected user.

Instances can also be managed from the command line inside the server container with `admin instances list`, `add` and `remove`.

## Maintenance {#maintenance}

Some work needs the server to stand still, for example restoring a backup. The operator switches the server into maintenance mode with `admin maintenance on`. While it is on, every page and request except the health probes and the metrics answers with 503, and the pages say "The server is in maintenance." Nothing is lost; try again later. The operator switches maintenance off after the work.

What the operator does is described in the operations documents that come with the server: backup and restore, rotating the master key, offboarding and the daily retention sweep. They need access to the server container and are not part of the web pages. If maintenance takes longer than expected, ask your operator.
