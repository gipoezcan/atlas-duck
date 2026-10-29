---
id: instances-and-tokens
title: Instances and tokens
mode: both
order: 30
---

## Instances {#instances}

An instance is one Jira or Confluence Data Center server that atlas-duck talks to. It is known by an alias, for example the short name of the server.

::: desktop

In desktop mode you define your own instances. Settings lists them under "Instances":

| Column | Content |
| --- | --- |
| Alias | The name you gave the instance. |
| Product | Jira or Confluence. |
| Origin | The confirmed address of the server, or "(not confirmed)". |
| State | See below. |
| Executes as | The Atlassian user your token belongs to. |
| Token expiry | The expiry date you entered, if any. |
| Proxy | The proxy of this instance, or "OS setting or none". |

The state tells you whether the instance can be used:

| State | Meaning |
| --- | --- |
| ok | Ready. |
| needs token | No token is stored yet. Use "Add token". |
| unconfirmed | You have not confirmed the origin yet. Use "Confirm instance". |
| insecure scheme (http) | The URL starts with http. atlas-duck requires https. If your server uses an internal certificate authority, add it as the instance's custom CA. |
| identity header missing | "X-AUSERNAME not received, possibly stripped by a reverse proxy in front of Jira; ask the Jira administrator". |
| identity header mismatch | The X-AUSERNAME header does not match the user of the token. |

:::

::: server

In server mode an admin defines the instances for everyone. You see them on the "Credentials" page and add only your own token for each. If the page says "No instance is configured yet. An admin adds instances.", ask your admin. Admins: see [Administration](admin#instances-admin).

:::

## Add an instance {#add-instance}

::: desktop

Open Settings, "Add an instance" (the setup window has the same form), and fill in:

- **Alias** and **Product** (Jira or Confluence).
- **Base URL (https, with the context path)**. atlas-duck requires https.
- **Proxy**, as host:port, `direct`, or empty for the OS setting. If your system uses a proxy auto-config script, atlas-duck does not evaluate it: set the proxy of the instance here.
- **Use a custom CA certificate** if your server uses an internal certificate authority. atlas-duck asks for the file.
- **Default instance for its product**. A product can have only one default instance.

Choose "Add instance". atlas-duck then shows the alias and the origin in its own dialog; confirm it. The message "The instance was added. Add its token next." follows. A row also offers "Change URL" and "Apply proxy" later.

:::

::: server

Users do not add instances in server mode. Ask your admin to add one. Before you store a token, check that the URL on the "Credentials" page is the server you mean.

:::

## Tokens {#tokens}

atlas-duck always acts as you, with your own personal access token (PAT), never with a shared service account. Create the token in Jira or Confluence (Profile → Personal Access Tokens) and give it only the permissions your work needs. Whatever the token may not do in Jira or Confluence, an agent cannot do either.

::: desktop

Enter the token in the [credential window](#credential-window). You can also enter an optional expiry date. atlas-duck then warns you ahead of time ("Token expires in N days", "Token expires today", "Token expired on ..."). This is only a warning: the server decides whether a token works.

On each instance row of Settings:

- "Add token" or "Replace token" opens the credential window.
- "Re-test stored token" asks the server again. The answer is "Connected as ...", or "The re-test failed:" with the reason.

:::

::: server

Enter the token on the [Credentials page](#credentials-page).

:::

When you store a token, atlas-duck first tests it against the instance. These are the reasons for a refusal:

| Reason | What to do |
| --- | --- |
| The server rejected the token (401). | Check that it is a valid personal access token that has not expired. |
| The token belongs to another user. | A token is already stored for a different Atlassian user. Remove the stored token first. |
| The TLS certificate of the server could not be verified. | If your server uses an internal CA, the instance needs it as its custom CA. |
| A proxy blocked or changed the connection. | Check the proxy settings. |
| The server could not be reached. | Try again later. |
| The server version is below the minimum atlas-duck supports. | The instance has to be upgraded. |

## Where tokens are stored {#token-storage}

::: desktop

Your tokens are kept in the operating system keychain of this computer. atlas-duck never shows a stored token again. Backups never contain tokens: after a restore, every instance needs its token again. "Prepare for removal" in Settings deletes the stored tokens and then asks you to revoke each token on its server.

:::

::: server

Your tokens are stored on the server, encrypted at rest with the server's master key. Operators who have access to that key can decrypt every stored token, so treat the server's key material as you would the tokens themselves. atlas-duck never shows a stored token again. Your tokens are deleted at once if your account is deactivated, and when an admin removes an instance, every user's token for it is deleted.

:::

Tokens give access to Jira and Confluence in your name. Rotate them regularly, and revoke a token on its server when you no longer need it.

::: desktop

## The credential window {#credential-window}

Tokens and passphrases are typed in a separate window, the credential window, and nowhere else. For a token it is titled "Add token" or "Replace token". Before you type, it shows the Instance, the Product and the Address, so you can check that you are talking to the right server. If some characters of the address are unusual, they are shown as escapes with a warning: check the address before you continue.

1. Paste the token into "Personal access token". Optionally fill in "Token expires on (optional)".
2. Choose "Test and store".
3. On success the window says "Connected as *user*, *product* *version*. You can close this window."

The same window asks for the recovery passphrase, to unlock atlas-duck and to restore a backup.

:::

::: server

## The credentials page {#credentials-page}

"Credentials" in the header lists every instance with its product, URL and token state:

| State | Meaning |
| --- | --- |
| No token | You have not stored one. |
| Token stored | The token works. The row shows the Atlassian user, for example "as jdoe". |
| Token stored, not usable | The stored token does not work any more. Replace it. |

Use "Add token" or "Replace token", enter the token in "Personal access token for *alias*" and choose "Check and save". "Remove" deletes your token for that instance after a confirmation. atlas-duck never shows a stored token.

Errors you may see: "The instance refused this token. Check it and try again."; "This token belongs to another Atlassian user. Remove the stored token first."; "This instance cannot be used right now. Ask an admin."; "The instance cannot be reached. Try again later."; "This instance no longer exists."; "The token is empty or too long."

:::
