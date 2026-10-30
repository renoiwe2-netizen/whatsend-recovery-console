# Private mobile desktop fixture

Minimal Docker console: Python aiohttp, TigerVNC, Chromium and the official noVNC touch UI. The default `RECOVERY_MODE=fixture` opens **only the bundled fictitious page**. An optional, separately configured `provider` mode supports administrator-initiated human login; optional server-authorized credential prefill is supported; submission remains manual.

## Render configuration

- Runtime: Docker; plan: **Free**; health check: `/health`.
- `POC_ACCESS_TOKEN`: a random **64-character hexadecimal** server secret. Never put it in this repository or a query string.
- Origin uses Render's `RENDER_EXTERNAL_URL` automatically. For a custom hostname set `POC_PUBLIC_ORIGIN=https://exact-host.example`.
- `PORT` defaults to `10000`. `POC_SECONDS` defaults to `600` and cannot exceed `600`.
- Chromium keeps its sandbox by default. If this isolated fixture reports `SANDBOX_UNAVAILABLE`, explicitly setting `POC_ALLOW_UNSANDBOXED=1` enables a **fixture-only benchmark** on restricted container kernels. This is not approval for real logins or production use.

Open `https://your-service.onrender.com/#token=YOUR_PRIVATE_TOKEN` privately. The fragment is removed immediately and exchanged for a host-only HttpOnly Secure SameSite=Strict cookie. Do not share screenshots of this link. The token can open another fixture after expiry; rotate the Render secret after testing.

The desktop starts only after authentication. `/health` never starts it. One session and one authenticated WebSocket at a time; strict Origin checking on creation, close and WebSocket. The desktop closes after ten minutes even if the tab is abandoned. The ordinary noVNC keyboard toggle supports mobile keyboards. Clipboard transfer is disabled.

Only `/health`, `/` and `/client.js` are public. Desktop assets, memory measurements and WebSocket require the session cookie. Browser policies and a closed local network route prevent browsing away from the bundled fixture. No server token is passed into Chromium's environment. No request, token or cookie access logs are emitted.

## Verify before calling it usable

Render Free has **512 MB RAM and 0.1 CPU**, sleeps after inactivity, and uses ephemeral storage. This package's HTTP/session tests do not prove Chromium fits that budget or performs well on a phone. Measure the container, interact with the fixture on 320px and 390px screens, and confirm automatic closure. Cold starts can be slow. Provider use requires the private relay configuration below.

Authenticated `/metrics` returns cgroup memory counters and a sanitized startup failure code. It never returns raw process logs. Codes include `SANDBOX_UNAVAILABLE`, `MEMORY_LIMIT_REACHED` and `BROWSER_UNAVAILABLE`.

Official references: [Render Free](https://render.com/docs/free), [compute plans](https://render.com/docs/compute-plans), [WebSockets](https://render.com/docs/websocket), [noVNC mobile support](https://novnc.com/info.html).

Upload allowlist: `Dockerfile`, `.dockerignore`, `bootstrap.sh`, `fixture.html`, `measure.py`, `server.py`, `recovery.py`, `automation.py`, `runner-loader.mjs`, `package.json`, `index.html`, `client.js`, `chromium-policy.json`, `README.md`. No `.env`, browser profile, private task source/bundle, tests, local Python environment or other project files.

## Optional private hosted tasks

Server-only settings `CF_ORIGIN`, `HOSTED_RUNNER_KEY` and `HOSTED_BUNDLE_SHA256` enable the authenticated task gateway. With no key the task routes return 404. The key must be 32–128 base64url characters; the bundle hash is 64 lowercase hexadecimal characters. Never put these values in browser links or this repository.

`POST /automation/run` accepts `Authorization: Bearer <server-key>` and JSON `{run_id, lease_token, mode}`. Both identifiers are UUIDs; mode is `send`, `report` or `import_reconcile`. It returns 202 while active. Repeating the same run and lease returns its current state without launching a second process. These routes refuse browser Origin headers.

`POST /automation/status` with the same authentication and `{run_id}` is read only. It returns `{run_id,status,process_closed,closure_source,boot_id}` and optional safe error code, numeric exit code and numeric cgroup memory counters. A lost in-memory record returns `status:unknown`. Closure is proven only while the gateway is idle, under its lock, with no same-user loader or private task browser in `/proc`; every scan error fails closed. A known run also requires the supervisor to have awaited process exit and removed its detached browsers. `boot_id` identifies this supervisor instance. A timeout, expired lease or absent record alone never proves closure. This endpoint never kills or starts a process.

The generic Node 22 loader downloads business code from the private relay at `/internal/hosted`, checks the configured SHA-256 before importing it, and stores it temporarily with restricted permissions. The public repository contains no business code or account configuration. All task calls carry the same run and lease; the relay must independently bind them to one authorized task and account. Database credentials, encryption keys and passwords stay on that relay.

The private runtime receives a `mediaDirectory` scoped to this run (0700). `call('media_stream',{index})` reads an authenticated binary response with URI-encoded JSON metadata in `X-Task-Media`, streams at most 10 MiB into one random local file (0600), and checks the exact declared size and SHA-256 before returning `{media,file_path}`. Its extension is restricted to 1–8 lowercase letters/digits. The runtime must unlink this file before requesting the next. No base64 media or complete binary buffer is retained in the loader. Stream reads and cleanup are bounded; POST requests are never replayed. The supervisor removes only the closed run's private temporary directory after a crash.

One browser runs at a time. An active human connection blocks a task; a running task blocks a new human connection. Idle desktops close before headless Chromium starts. Chromium retains its sandbox and receives no server secrets. Tasks have a 180-second operation deadline and bounded closure; a 205-second process watchdog also removes detached Chromium groups belonging to that exact temporary run profile. The relay must enforce the shared account lease independently of this in-memory gateway. A lost submission result requires review, never an automatic second submission.

## Optional human recovery adapter

Enable only after configuring a trusted capability relay and testing the full integration. Server-only settings: `RECOVERY_MODE=provider`, `RECOVERY_HELPER_URL`, `PROVIDER_ORIGIN`, `PROVIDER_LANDING_PATH`, `PROVIDER_PROFILE_PATH`, `PROVIDER_AUTH_MARKER`, `PROVIDER_LOGIN_FORM`. Optional settings: `PROVIDER_LOGIN_PATH`, `PROVIDER_LOGIN_SUBMIT_PATH`, `PROVIDER_NATIVE_READY_SELECTOR`; JSON arrays `PROVIDER_READ_PATHS`, `PROVIDER_ASSET_PREFIXES`, `PROVIDER_CHALLENGE_ORIGINS`, `PROVIDER_STATIC_ORIGINS`.

The administrator's 43-character single-use capability is passed as `#ticket=...` and checked by the relay before any browser starts. The user signs in manually in a fresh temporary profile. Optional `PROVIDER_PREFILL_ENABLED=1` obtains existing credentials from the private relay using server-only `RECOVERY_RELAY_KEY`. Only the exact empty login form is filled once, before the viewer opens; no click, submit or verification is automated. Credentials are not stored in Render environment variables, returned by browser APIs or passed into Chromium environment. Chromium keeps its sandbox; fixture sandbox overrides are ignored. Exact network allowlists permit the login and its native verification resources, never campaign submission. Native verification readiness is read only as a boolean; no CAPTCHA solution or token is extracted/injected.

After a recognized authenticated screen, two read-only navigations capture account identity and origin-scoped session cookies. The browser closes before the encrypted-storage relay is called. The relay must independently verify identity and atomically commit the session. A lost acknowledgement retries the same capability and bundle at most once; no browser action is replayed. Only relay confirmation displays `connected`. Cancellation/expiry closes the temporary browser and aborts the capability; forced process loss is bounded by the relay's ten-minute lease. No passwords or browser profiles survive cleanup.

The generic adapter's offline tests do not prove that a particular provider accepts cloud login. A native challenge refusal remains a refusal; this console does not evade it.


Native verification readiness: observe only SDK/result presence booleans. Wait up to40seconds before showing login; show a conservative expiry warning after90seconds. Manual refresh reuses the same temporary browser and original10minute lease. It never submits login or solves verification. Optional prefill credentials remain only in private session RAM for this bounded refresh and are cleared on verification or closure; public HTTP responses never include them.
