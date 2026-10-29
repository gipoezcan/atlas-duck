---
id: approvals
title: Approvals
mode: both
order: 50
---

## The approval queue {#queue}

Nothing an agent asks for leaves atlas-duck without your decision. Every request that needs one waits in the queue under "Pending approvals". When nothing waits, the list says "No pending requests".

::: desktop

The Approvals window is the main window of the desktop app. Its header gives you the other windows: Settings, Audit, Running scripts, Onboarding and Quit. A banner under the header starts with "Caution:" or "Info:" when something needs your notice.

:::

::: server

After you sign in, the Approvals page is your start page. Its header leads to the other pages of the server.

:::

Requests are grouped by session, so you see which agent run sent what. Each row shows:

- the class of the request: "Read", "Write" or "Script";
- the agent's reason, or "no reason given";
- how long the request has waited;
- warnings: "stale" (its revision changed after you opened it, so open it again), "caution" (see [Unverified text](approvals#unverified-text)), "possible duplicate" and "similar request" (an earlier request of the same agent looks alike).

Use "Open" to look at a request. Use "select" to include a row in a [batch decision](approvals#batch-decisions), or "select all from session" to select all rows of one session.

A request that nobody decides expires. The agent then receives `expired`.

## Reading a request {#reading-a-request}

Opening a request fills the detail pane, "Request detail". At first the pane only offers "Open preview". Opening the preview is what makes a decision possible: you decide on what you have seen.

The pane has four tabs:

| Tab | Content |
| --- | --- |
| Preview | What would be executed or sent to the agent, in readable form. |
| Structured | The same content as a tree; here you edit or redact. |
| Raw | The exact content, page by page. |
| Request | Who asked for what. |

The "Request" tab lists:

- Params and their `params_sha256` fingerprint;
- Reason, Instance, Operation and Target;
- Requested limits (scripts only);
- Submitted and Age;
- Connection, Client kind, Agent name, Agent name source and `cwd_basename`;
- Connection id.

::: desktop

On the desktop the tab also shows the peer details: Peer pid, Peer exe, origin exe and Peer chain.

:::

The agent name is chosen by the agent. Treat it as a label, not as proof of who is asking.

## Approve, release or deny {#approve-or-deny}

The buttons depend on the class of the request:

| Request | Buttons | What happens |
| --- | --- | --- |
| Write | "Approve" | atlas-duck executes the change. |
| Read | "Release" | The data the instance returned is handed to the agent. |
| Script | "Release" | The final result of the script is handed to the agent. |
| Read that failed with an HTTP error | "Release" or "Release status only" | The agent receives `failed` (exit 6) with the HTTP status, with the text of the error ("Release") or without it ("Release status only"). |
| Read that failed without an HTTP answer, or was too large | "Release outcome" | The agent receives `failed` (exit 6) with the outcome class (`result_too_large`, `upstream_network` or `upstream_unavailable`) and a fixed message; no HTTP status and no size. |
| Any | "Deny" | The agent receives `denied` (exit 3) and your reason. |

Under the buttons the pane states in one line what the agent will receive.

Shortcuts: Ctrl/Cmd+Shift+Enter approves or releases, Ctrl/Cmd+Shift+D denies, Ctrl/Cmd+Shift+Down and Ctrl/Cmd+Shift+Up move to the next and previous request.

To deny, "Deny" opens "Deny this request". Type the "Reason for the agent" and press Enter, or use "Send deny"; Esc cancels. The agent sees your reason, so write it for the agent. You can also "Attach a hint": at most one hint, chosen from the offered ones, for example the HTTP status of the instance, the outcome class, the name that could not be resolved, or the missing required fields. The hint helps the agent to try again with better input.

## Editing and redacting {#edit-and-redact}

You can change what is executed, or hold back parts of what is released. Both create a new revision of the request. atlas-duck never changes the old revision.

**Edit a write.** "Edit before approving" shows the parameters as fields. Fields that name the target are marked "read-only: deny to retarget"; if the target is wrong, deny and let the agent ask again. Missing required fields are listed under "Missing required fields". "Edit & approve" sends your edit; "Reset edits" discards it. An edit gives a new revision: open its preview, check it, then approve it as a second step. Edits that you have not sent keep "Approve" disabled ("Unsent edits…").

**Redact a read or a script result.** "Redact before releasing" shows the candidate, the data that would go to the agent, as a tree. You can:

- "Drop item": leave out one entry of a list;
- "Drop field (this item)" or "Drop field (all items)": leave out a field;
- "Mask text": replace a text with `[REDACTED]`. Enter the "Text to mask", or use the selected text. "Only this occurrence" masks one place only;
- use a preset: "Release status only" or "Keep error class only";
- "Remove all redactions" to start over.

Pressing "Release" sends the redactions and creates a new revision. Open it, check what the agent would receive ("Released size" shows the number of bytes), then release it.

If the text you want to mask also appears elsewhere, atlas-duck tells you where. "Release anyway: the other occurrences stay in what the agent receives" is your explicit choice to leave them.

**When a release is blocked.** atlas-duck refuses a release that could leak what you redacted, and says why:

| Message | Meaning and what to do |
| --- | --- |
| a masked text still occurs | The text is still present, for example in another field, or in a place that cannot be rewritten such as a field name or a number. Mask it elsewhere, or drop the item or the field. |
| a value still changes after 3 decoding rounds | A value is encoded in layers that cannot be checked reliably, or it is too large to check. Drop the item or the field. |
| a match could not be masked cleanly | The text sits inside an encoded value. Drop the item or the field instead. |
| a mirrored entry has no counterpart | Two lists in the result belong together and one entry has no partner. Use "Drop the flagged items". |
| mirrored entries cannot be matched | The same, but atlas-duck cannot tell which entries belong together. Use "Drop the flagged items". |
| a redaction names nothing in the candidate | The redaction no longer fits the data. Remove it. |
| the redacted candidate is over the 16 MiB release cap | The result is too large to release. Drop items or fields, or deny. |

When entries have no counterpart, the pane lists them ("These entries have no counterpart and block the release:"). If the candidate cannot be built exactly, the release is blocked as well; deny the request or drop the flagged entries.

## Batch decisions {#batch-decisions}

When many similar requests wait, decide them together. Select the rows, or use "select all from session", and the "Batch decision" bar appears. "Approve or release N selected" first shows what will happen, for example how many reads and scripts are released and how many writes are approved. You then confirm with "Confirm batch", and the desktop app asks once more with a native confirmation.

A batch is all or nothing. If even one request changed in the meantime, the whole batch is refused: "The batch was rejected and nothing was decided". The reason is given for each request:

- its revision changed (stale);
- its preview was not opened;
- it is not approvable;
- it is flagged as a possible duplicate or similar request, and must be approved individually;
- it is no longer pending;
- its target cannot be edited.

A request that you want to look at yourself can be taken out of the batch: it then shows "Not part of the batch", or you choose "individually".

To say no in bulk, use "Deny selected" or "Deny all pending from this session". Both ask for a reason for the agent and send it with "Send deny".

## Needs attention {#needs-attention}

Below the queue, "Recently decided (24 h)" lists what was decided in the last day. Entries under "Needs attention" are approved writes that did not end well: the write failed, ended with an unknown outcome, or met a version conflict. "check target" tells you to look at the Jira or Confluence object yourself, because for an unknown outcome atlas-duck cannot tell whether the change happened.

A write that was sent back to the queue because the request changed before it ran ("returned for re-review") is pinned there as well. Use "Acknowledge" to take an entry off the list, or "Acknowledge all". Acknowledging is not saved: after atlas-duck restarts, the entries can appear again. When nothing was decided, the list says "Nothing decided in the last 24 hours".

The status labels you will meet are: pending, executing, succeeded, released, denied, expired, cancelled, failed, abandoned, outcome unknown and "returned for re-review".

## Unverified text {#unverified-text}

Everything an agent writes is untrusted: the reason, the agent name and the parameters. atlas-duck therefore marks what it could not check.

- "unverified" marks a text that was written by the agent and not checked.
- "unusual characters" marks a text with characters that are invisible or easy to mix up with others. They are shown in escaped form, so that you can see them.
- "Caution:" in a request is a warning from atlas-duck that you should read the request closely before you decide.

Read marked text slowly, and deny when in doubt. Denying costs the agent one new request; approving a wrong request can cost you a change that cannot be undone.
