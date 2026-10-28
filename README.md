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

Upload allowlist: `Dockerfile`, `.dockerignore`, `bootstrap.sh`, `fixture.html`, `measure.py`, `server.py`, `recovery.py`, `index.html`, `client.js`, `chromium-policy.json`, `README.md`. No `.env`, browser profile, local Python environment or other project files.

## Optional human recovery adapter

Enable only after configuring a trusted capability relay and testing the full integration. Server-only settings: `RECOVERY_MODE=provider`, `RECOVERY_HELPER_URL`, `PROVIDER_ORIGIN`, `PROVIDER_LANDING_PATH`, `PROVIDER_PROFILE_PATH`, `PROVIDER_AUTH_MARKER`, `PROVIDER_LOGIN_FORM`. Optional settings: `PROVIDER_LOGIN_PATH`, `PROVIDER_LOGIN_SUBMIT_PATH`, `PROVIDER_NATIVE_READY_SELECTOR`; JSON arrays `PROVIDER_READ_PATHS`, `PROVIDER_ASSET_PREFIXES`, `PROVIDER_CHALLENGE_ORIGINS`, `PROVIDER_STATIC_ORIGINS`.

The administrator's 43-character single-use capability is passed as `#ticket=...` and checked by the relay before any browser starts. The user signs in manually in a fresh temporary profile. Optional `PROVIDER_PREFILL_ENABLED=1` obtains existing credentials from the private relay using server-only `RECOVERY_RELAY_KEY`. Only the exact empty login form is filled once, before the viewer opens; no click, submit or verification is automated. Credentials are not stored in Render environment variables, returned by browser APIs or passed into Chromium environment. Chromium keeps its sandbox; fixture sandbox overrides are ignored. Exact network allowlists permit the login and its native verification resources, never campaign submission. Native verification readiness is read only as a boolean; no CAPTCHA solution or token is extracted/injected.

After a recognized authenticated screen, two read-only navigations capture account identity and origin-scoped session cookies. The browser closes before the encrypted-storage relay is called. The relay must independently verify identity and atomically commit the session. A lost acknowledgement retries the same capability and bundle at most once; no browser action is replayed. Only relay confirmation displays `connected`. Cancellation/expiry closes the temporary browser and aborts the capability; forced process loss is bounded by the relay's ten-minute lease. No passwords or browser profiles survive cleanup.

The generic adapter's offline tests do not prove that a particular provider accepts cloud login. A native challenge refusal remains a refusal; this console does not evade it.

