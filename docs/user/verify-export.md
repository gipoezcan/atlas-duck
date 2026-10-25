# Compliance exports and `verify-export`

This page has two readers. The person who makes an export (in the Audit window) reads "Making an export" and "Where the files are readable". The person who receives an export (an auditor, a lawyer, a compliance owner) reads "Verifying an export".

## Making an export

Open the Audit window, "Export and backup", "Compliance export". Fill in "Export from (UTC)" and "Export to (UTC)", or leave both empty for the whole log, and choose "Export…". atlas-duck first shows a native warning that the export holds decrypted payloads, then asks for a folder in its own dialog. The export goes into a new folder inside the folder you chose:

`atlas-duck-export-<chain id>-<first seq>-<last seq>-<UTC time>`

The folder holds three files:

- `events.jsonl`: one line per audit record in the range. Every column of the record, the encrypted payload as base64 and the decrypted payload (`payload_b64` always, and `payload` as readable JSON when it is small enough). If an anchor directory is configured, records after its last anchored line carry `"unanchored": true`.
- `prune_log.jsonl`: every row of the prune log. It is empty if the log was never pruned.
- `manifest.json`: written last. It holds the range, the first and last sequence numbers, the head record, the chain ids, the restore and key-recovery records in the range, the SHA-256 of the two other files, and the accountability statement: the OS user who approves a request acts as the owner of the access token and is the accountable person. Agent and program names in the log are advisory.

When the export is complete, atlas-duck logs it as an `EXPORT` record and shows the SHA-256 of `manifest.json`: "Give the recipient this SHA-256 by another channel". Do exactly that. The hash is the trust anchor, so it must not travel in the same package as the export.

The folder name shown at the end ("The export is complete: N records in the folder ... inside the folder you chose") is the folder to hand over.

### Where the files are readable

- The files are decrypted. Any program that runs as your user can read them. They are outside the retention period and outside the shredding of old months. You are responsible for keeping and deleting them.
- macOS and Linux: the export folder is created with mode 0700 and every file with mode 0600, so only your user can read them.
- Windows: the files take over the access rights of the folder you chose. atlas-duck does not set its own. Choose a folder that only you can read, not a shared folder, not a synced folder others can see and not a folder with open "Everyone" or "Users" rights.
- Do not send an export by e-mail or chat. Copy it to a medium or share that only the recipient can read.

### A failed or interrupted export

- "Cancel export" and a normal failure remove the unfinished folder and write no `EXPORT` record. Quitting atlas-duck during an export cancels it and waits for it to end.
- While it runs, the export is written into a folder whose name ends in `.partial`. It gets its final name only after the `EXPORT` record is written. A folder named `atlas-duck-export-....partial`, or any export folder without a `manifest.json`, is not an export. It is an incomplete or failed one and may hold decrypted audit data. Delete it.
- If atlas-duck stops while an export runs (crash, killed process, power loss, forced shutdown), the `.partial` folder stays with whatever was written, including a decrypted `events.jsonl`. Nothing removes it later. Look for such folders in the folder you chose and delete them.
- If atlas-duck says the unfinished folder "could not be removed", it holds decrypted data: delete it yourself.
- If atlas-duck says the export is complete and logged but "its folder kept the name ...", remove `.partial` from the end of the folder name before you hand it over. Do not export again.
- `verify-export` refuses a folder whose name ends in `.partial` and exits with 22. If you know the export is complete (the case in the last item), rename the folder first.

## Verifying an export

`verify-export` is a command of the atlas-duck command line:

```
atlas-duck verify-export <dir> [--anchor-dir <dir>] [--manifest-sha256 <64 lowercase hex>]
```

- `<dir>` is the export folder.
- `--anchor-dir <dir>` is the external anchor directory the export was anchored to (a read-only copy is enough).
- `--manifest-sha256 <hex>` is the SHA-256 of `manifest.json` that you received through a different channel. It must be 64 lowercase hexadecimal digits.
- `verify-export` must be the first argument. The global CLI flags do not apply to it. `--help` or `-h` anywhere shows the built-in help (to check a folder named like a flag, write `./--help`).

Example:

```
atlas-duck verify-export D:\audit\atlas-duck-export-... --manifest-sha256 <the hash you were given>
```

You need atlas-duck installed on the verifying machine. The command line starts the atlas-duck app in a read-only mode as a child process. That mode needs no running app, no keychain and no key. It reads only the export folder, the anchor directory and the hash you give it. It does not open the live audit log. The report goes to standard output, as plain lines and not as a JSON envelope. Problems with the command itself go to standard error.

### Which app is started

The command line starts the app it finds: first the AppImage that the command line itself runs from (Linux), then the app next to the `atlas-duck` program, then the path recorded in `cli.toml`. `verify-export` trusts that program. If somebody replaced it, it can print any result. So verify on a machine whose atlas-duck installation you trust, installed from the project's own package, and not from a program that the exporter or a third party sent you with the export.

If no app is found, the command prints "atlas-duck app not found; reinstall or re-run Install CLI to PATH" and exits with 22.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Verified against a trust root you supplied (`--manifest-sha256` or `--anchor-dir`, see below). |
| 20 | The export is consistent with itself, but no trust root you supplied covers all of it: "internally consistent; trust root NOT verified". |
| 21 | Tampering or a fork was found. The report says what. |
| 22 | Usage or I/O error: bad arguments, an unreadable or missing file, a `.partial` folder, a file that is not an export file, a record or settings format of another version, a size limit exceeded, the app not found, or the app ended abnormally (a crash gives 22, never 0). |

Only 0, 20, 21 and 22 come from the verifier. Treat anything but 0 as "not verified". Exit 20 is not a pass: it says the export has no inner contradiction and nothing more. Someone who builds a new, consistent log from scratch passes the inner checks.

The last line of the report names the result: "verified against the manifest SHA-256", "verified against the anchor dir", "verified against the manifest SHA-256 and the anchor dir", "internally consistent; trust root NOT verified", a line starting with "TAMPERED:" or "FORK:", or a line starting with "cannot verify:".

### What is checked

The verifier recomputes every record hash from the columns of its line and the chain from the boundary hash in the manifest to the head. It checks the digest and length of every decrypted payload, the request-set hash of every approved write against its list of requests, the prune log (its own hash chain and that its rows join up), the boundaries of restores, and the anchor lines when you give an anchor directory. It also checks that the files are the ones the manifest names. It needs no decryption key: the decrypted payload is in the file and the check is against the record's stored digest. Other entries that sit in the export folder next to the three files are named in the report and never checked.

### What each trust root proves

The result depends on what you supply.

- **With the manifest hash** (`--manifest-sha256`), the verifier first compares it with the SHA-256 of `manifest.json`. A different manifest gives exit 21 ("TAMPERED: manifest.json is not the manifest the given SHA-256 names"). The manifest in turn holds the hashes of `events.jsonl` and `prune_log.jsonl`, so the manifest hash binds every byte of the export. If everything else checks out, the result is exit 0. The hash must come from the exporter by another channel. A hash that you computed from the manifest you received proves nothing.
- **With the anchor directory alone** (`--anchor-dir`), the verifier compares the anchored `{seq, record hash}` lines with the records of the export. This binds the export up to the last record that an anchor line names. Exit 0 only if that last anchored record is the last record of the export. Otherwise it exits with 20 and says "anchor dir: ok up to seq N; rows N+1..M unanchored, not covered by a trust root; give --manifest-sha256". The tail of an export, the records written after the last anchor line, is an unanchored tail. It needs the manifest hash. If no anchor line names any record of the export, the anchor directory verified nothing.
- **With both**, both must hold. The last line then names the anchor directory only if one of its lines names a record of the export.
- **With neither**, the result is exit 20: "internally consistent; trust root NOT verified".

An anchor directory protects against a rewritten history only if the person who is audited cannot write to it (for example a share run by someone else). Ask who can write to it.

### A fork

An export that continues a log that was restored (see [offboarding.md](offboarding.md)) has a new chain id. If you hold two exports that share the same start and then differ, with different chain ids, `verify-export` reports a fork ("FORK: ...", exit 21). This is not proof of tampering. It shows that two copies of the log ran next to each other, usually because the old installation was not decommissioned after a restore. Ask the operator which installation is the real one and whether the other was removed.

### What an export does not prove

An export shows what was in the log. It does not show that the log was complete if the audited user deleted data, reinstalled or confirmed a destructive action on a machine without an external anchor directory. See [threat-model-limits.md](threat-model-limits.md).
