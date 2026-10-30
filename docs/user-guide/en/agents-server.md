---
id: agents-server
title: Agents (server)
mode: server
order: 41
---

## API keys {#api-keys}

An API key lets an agent reach atlas-duck over MCP on your behalf. A key never approves anything: every request of the agent still waits in your [approval queue](approvals#queue).

Open "API keys" from the header. To create a key:

1. Enter a "Name" of 1 to 64 characters, for example the name of the agent or the tool.
2. Select the scopes, see [Scopes](agents-server#scopes). Select at least one.
3. Enter "Expires in (days, 1–90)".
4. Choose "Create key".

atlas-duck shows the key once: "This key is shown only now." Use "Copy", paste it into the settings of your agent, and choose "Done". atlas-duck cannot show it again. If you lose it, create a new one.

The agent sends the key as `Authorization: Bearer adk_…`. The list shows for each key the Name, the Prefix (the first characters, to recognise it), the Scopes, when it Expires and was Last used, and its State: Active, Revoked or Expired. You can have at most 25 active keys.

"Revoke" stops a key. atlas-duck asks first: agents using it stop working at once. Revoke every key that you no longer use, and every key that may have leaked.

## Scopes {#scopes}

A scope says what a key, or an app, may ask for. Pick the smallest set that the agent needs.

| Scope | Meaning |
| --- | --- |
| `read` | Read data and wait for your decisions. |
| `propose_write` | Propose changes for your approval. |
| `scripts` | Run read-only scripts in the sandbox; you approve each final result. |

Even with every scope, an agent cannot decide anything. What it reads reaches it only after you release it, and every change needs your approval. See [Approvals](approvals#approve-or-deny) and [Scripts](scripts#what-are-scripts).

## Connected apps {#connected-apps}

"Connected apps" lists the apps that you allowed to use atlas-duck over MCP with OAuth. An app never approves anything either.

The table shows the App, "Returns to" (the address that the app returns to after you answered), the Scopes, when you Allowed it, when it was Last used and when it Expires, and its State: Active, Revoked or Expired.

"Revoke" cuts an app off: "The app loses access at once." The app has to ask for your permission again if it wants to return.

OAuth is on by default. Your operator can switch it off; the server then no longer offers the flow and answers "OAuth is not enabled on this server." If you cannot use OAuth, ask your administrator; API keys keep working.

## Authorising an app {#oauth-consent}

When you add atlas-duck to an MCP client that supports OAuth, the client opens your browser on the page "Allow an app to use atlas-duck?". Sign in first if atlas-duck asks. The page shows:

- the name of the app, marked "unverified, chosen by the app": anybody can pick any name, so do not trust it;
- "After your answer you return to": the address that your browser goes to next. Check that you expect it;
- what "It asks to" do: `read` is always included, `propose_write` and `scripts` appear when the app asks for them.

You can switch off scopes, but never add one. Choose "Allow" or "Deny". If you are unsure about an app, choose "Deny": nothing is allowed. You can revoke an allowed app at any time under "Connected apps". Every authorization asks again; atlas-duck does not remember the answer for the next app.

An app keeps its access with short-lived tokens that it renews by itself. An access grant lasts 90 days at most.

## The MCP endpoint {#mcp-endpoint}

The MCP endpoint of the server is its public address followed by `/mcp`, for example `https://atlas-duck.example.org/mcp`. Your administrator tells you the address.

An agent or an app connects to it as a remote MCP server:

- With an API key, set the header `Authorization: Bearer adk_…`.
- With OAuth, the client finds out for itself where to sign in: it asks `/mcp`, reads the `.well-known` documents of the server, registers as a public client and uses PKCE. You only see the page "Allow an app to use atlas-duck?".

The tools are the same as on the desktop: operations, `script_run` (needs the `scripts` scope), and the request tools to await, check, cancel and list requests. Requests, statuses and errors mean the same as on the desktop; see [Error reference](error-reference).

Neither a key nor an app can use the approval functions of the server. Decisions can only be made by you, signed in in the browser.
