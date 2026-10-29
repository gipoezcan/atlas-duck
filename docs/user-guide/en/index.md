---
id: index
title: Overview
mode: both
order: 10
---

This guide is for the people who use atlas-duck: users and, in server mode, admins and auditors.

## What atlas-duck is {#what-is-atlas-duck}

atlas-duck lets AI agents read Jira and Confluence Data Center and propose writes that you approve. Every action is recorded in a tamper-evident audit chain.

There are two ways to run it:

- **Desktop mode**: atlas-duck is installed and runs on your own machine. It serves you and the agents that run on that machine.
- **Server mode**: your organisation hosts atlas-duck once, on its own network. It serves many users and their agents, and nothing is installed on your machine: you use it in a browser.

Both modes work the same way for you. These terms come back on every page:

| Term | Meaning |
| --- | --- |
| Agent | An AI program that acts on your behalf through atlas-duck. It proposes writes but never approves them. |
| Instance | One Jira or Confluence Data Center server that atlas-duck talks to, known by an alias. |
| Personal access token (PAT) | Your own Jira or Confluence token. atlas-duck always acts as you, never as a shared service account. |
| Approval | Your explicit yes or no to one proposed write before it reaches an instance. Every write needs one, in both modes. |
| Audit chain | Your tamper-evident record of everything atlas-duck did for you. Each user has one, in both modes. |

::: server

In server mode there are three more terms:

| Term | Meaning |
| --- | --- |
| Domain login | You sign in with your organisation's directory username and password. The password is checked against the directory and never stored. |
| Role | What you may do: user, auditor or admin. Roles come from your directory groups. |
| API key | A secret you create, with scopes and an expiry, that lets an agent act for you without a browser sign-in. |

:::

## How a request flows {#how-it-works}

1. An agent asks atlas-duck for something, for example to read a Jira issue or to change one.
2. The request appears in your approvals. Nothing reaches the instance yet.
3. You decide. You approve a write, release the result of a read or a script to the agent, or deny the request. An agent can never approve anything.
4. After your approval, atlas-duck sends the request to the instance as you, with your own personal access token.
5. atlas-duck records what happened in your audit chain.

A request that nobody decides expires.

## Where to start {#where-to-start}

::: desktop

1. [Getting started (desktop)](getting-started-desktop) installs atlas-duck and walks through the first start.
2. [Instances and tokens](instances-and-tokens) connects your Jira and Confluence servers.
3. [Agents (desktop)](agents-desktop) shows how an agent reaches atlas-duck.

:::

::: server

1. [Getting started (server)](getting-started-server) covers signing in, your tokens and your first agent.
2. [Instances and tokens](instances-and-tokens) explains the credentials page.
3. [Agents (server)](agents-server) covers API keys and connected apps.

:::

Then read [Approvals](approvals), the page you will use most, and [Audit log](audit). If something goes wrong, see [Troubleshooting](troubleshooting) and the [Error reference](error-reference).
