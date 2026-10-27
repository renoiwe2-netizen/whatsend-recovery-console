# Private mobile desktop fixture

Minimal Docker benchmark: Python aiohttp, Xvfb, Chromium, x11vnc and the official noVNC touch UI. It opens **only the bundled fictitious page**. There is no external login, account data, session synchronization or production integration.

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

Render Free has **512 MB RAM and 0.1 CPU**, sleeps after inactivity, and uses ephemeral storage. This package's HTTP/session tests do not prove Chromium fits that budget or performs well on a phone. Measure the container, interact with the fixture on 320px and 390px screens, and confirm automatic closure. Cold starts can be slow. Do not attach real credentials to this experiment.

Authenticated `/metrics` returns cgroup memory counters and a sanitized startup failure code. It never returns raw process logs. Codes include `SANDBOX_UNAVAILABLE`, `MEMORY_LIMIT_REACHED` and `BROWSER_UNAVAILABLE`.

Official references: [Render Free](https://render.com/docs/free), [compute plans](https://render.com/docs/compute-plans), [WebSockets](https://render.com/docs/websocket), [noVNC mobile support](https://novnc.com/info.html).

Upload allowlist: `Dockerfile`, `.dockerignore`, `bootstrap.sh`, `fixture.html`, `measure.py`, `server.py`, `index.html`, `client.js`, `chromium-policy.json`, `README.md`. No `.env`, browser profile, local Python environment or other project files.
