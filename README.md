# Apps Script connector for Claude

A remote MCP server that lets Claude read and edit Google Apps Script projects. It runs on
Google Cloud Run (free tier) and is added to claude.ai as a custom connector.

## What it can do

| Tool | What it does |
| --- | --- |
| `get_project` | Title, bound file, created and updated times |
| `get_project_content` | Read every file, one file, or a saved version |
| `edit_file` | Replace an exact piece of text in one file (must match once) |
| `write_file` | Create a file or replace a whole file |
| `delete_file` | Delete a file (not the manifest) |
| `create_project` | New standalone or bound project |
| `list_versions` / `create_version` / `restore_version` | Snapshots and rollback |
| `list_deployments` / `create_deployment` / `update_deployment` | Web app and API deployments |
| `list_executions` | Recent runs with status, to see if triggers ran or failed |
| `list_script_projects` | Only with `ENABLE_DRIVE_LISTING=true` (needs a restricted Drive scope) |

Edits save to the project's current code at once, the same as pressing Save in the editor.
Triggers use the new code on their next run. Every edit tool takes `create_version_first: true`
to snapshot the old code first.

## How sign-in works

- The server is its own OAuth server for Claude: dynamic client registration, PKCE S256,
  refresh tokens, `401` + `WWW-Authenticate: resource_metadata` discovery.
- Behind it, the user signs in with Google (offline access). Google's tokens are sealed with
  AES-GCM inside the codes and tokens the server issues, so there is no database.
- Only accounts in `ALLOWED_EMAILS` can finish sign-in. Other accounts get revoked and refused.
- Redirects are limited to `https://claude.ai/api/mcp/auth_callback` and loopback addresses
  (Claude Code).
- Tradeoff of being stateless: a stolen refresh token keeps working until Google access is revoked
  at https://myaccount.google.com/permissions or `TOKEN_SECRET` is rotated. Rotating
  `TOKEN_SECRET` (`./deploy.sh --set-google-client` makes a new one) signs Claude out at once.

## Settings (Cloud Run environment variables)

`deploy.sh` sets these for you.

| Name | Required | Value |
| --- | --- | --- |
| `GOOGLE_CLIENT_ID` | yes | Google OAuth web client id |
| `GOOGLE_CLIENT_SECRET` | yes | Google OAuth web client secret |
| `ALLOWED_EMAILS` | yes | Comma-separated Google accounts, e.g. `nate.d.holmes@gmail.com` |
| `PUBLIC_BASE_URL` | yes | The service URL, e.g. `https://apps-script-mcp-<project-number>.us-central1.run.app` |
| `TOKEN_SECRET` | no | Separate sealing key (deploy.sh makes a random one); defaults to the client secret |
| `ENABLE_DRIVE_LISTING` | no | `true` adds `list_script_projects` |
| `EXTRA_REDIRECT_URIS` | no | More allowed OAuth redirect URIs |

The client secret and token secret are plain environment variables on the service, visible only to
people with access to the Cloud project. Rotating either one signs Claude out.

## Setup

1. Turn on the Apps Script API for the Google account: https://script.google.com/home/usersettings
2. Create a Google Cloud project and link billing:
   https://console.cloud.google.com/billing/projects
3. Google Auth Platform: set up branding (External audience), then publish the app on the
   Audience page (https://console.cloud.google.com/auth/audience). Apps left in Testing lose
   their sign-in after 7 days.
4. Open Cloud Shell (https://shell.cloud.google.com), then:

   ```bash
   gcloud config set project YOUR_PROJECT_ID
   git clone https://github.com/NateD2000/apps-script-mcp.git
   cd apps-script-mcp
   ./deploy.sh
   ```

   The script turns on the APIs, prints the redirect URI, asks for the Google client id and
   secret (create a Web application client at https://console.cloud.google.com/auth/clients with
   that redirect URI), deploys, keeps only the 2 newest images, and adds a $1 budget alert.
5. In Claude: Customize > Connectors > Add custom connector, and paste the connector URL the
   script prints (`.../mcp`).

Google shows an "unverified app" warning on sign-in. Choose Advanced, then continue.

To ship code changes later: `git pull && ./deploy.sh`. To change the Google client:
`./deploy.sh --set-google-client`.

## Cost

Cloud Run's free tier covers 2 million requests, 180,000 vCPU-seconds and 360,000 GiB-seconds a
month. Cloud Build gives 2,500 free build-minutes a month and Artifact Registry 0.5 GB of free
storage. The service scales to zero when idle. A billing account is still required.

## Tests

```bash
deno task test
```
