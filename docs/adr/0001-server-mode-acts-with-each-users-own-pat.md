# Server mode acts with each user's own PAT, never a service account

In server mode atlas-duck could have used one Jira/Confluence service account and enforced per-user permissions itself, which would avoid storing many users' tokens on one server. We chose to store each user's own PAT (encrypted under a per-user data key) and always act as that user, so Jira's and Confluence's own permission checks and audit trails stay exact and atlas-duck never holds more access than the person approving the write.

## Considered Options

- Shared service account plus atlas-duck-side permissions: rejected, it silently grants everyone the account's reach and makes the Jira audit trail name the bot.
- OAuth / impersonation through Atlassian application links: depends on per-instance admin setup; may be added later alongside PATs.
