"""Isolated local-page benchmark. No provider login, session export or prod API."""
import asyncio
import contextlib
import hmac
import mimetypes
import os
from pathlib import Path
import re
import secrets
import signal
import tempfile
import time
from urllib.parse import urlsplit

from aiohttp import web, WSMsgType
from measure import snapshot
from recovery import CDP, Configuration, Relay, RecoveryError, configure_policy

ROOT = Path(__file__).resolve().parent
COOKIE = 'fixture_session'
# Debian bookworm provides aiohttp 3.8; AppKey was added later.
STATE = 'fixture_gateway'


class Browser:
    """One fresh, disposable, network-disabled desktop per authenticated session."""
    def __init__(self, config=None):
        self.processes = []
        self.directory = None
        self.oom_before = 0
        self.config = config
        self.cdp = None
        self.failure = None

    async def spawn(self, *args):
        # Do not give access tokens, Render metadata or server secrets to Chrome.
        env = {key: os.environ[key] for key in ('PATH', 'HOME', 'LANG') if key in os.environ}
        env.update(DISPLAY=':99', TMPDIR=self.directory.name)
        with open(Path(self.directory.name) / 'process-errors.log', 'ab') as errors:
            process = await asyncio.create_subprocess_exec(
                *args, env=env, stdout=asyncio.subprocess.DEVNULL,
                stderr=errors, start_new_session=True)
        self.processes.append(process)

    async def start(self):
        self.directory = tempfile.TemporaryDirectory(prefix='fixture-')
        self.oom_before = self.oom_count()
        await self.spawn('Xvfb', ':99', '-screen', '0', '320x640x24', '-nolisten', 'tcp')
        for _ in range(150):
            if Path('/tmp/.X11-unix/X99').exists():
                break
            if not self.alive():
                raise RuntimeError('DISPLAY_UNAVAILABLE')
            await asyncio.sleep(.1)
        else:
            raise RuntimeError('DISPLAY_UNAVAILABLE')
        await self.spawn('x11vnc', '-norc', '-display', ':99', '-listen', '127.0.0.1',
                         '-localhost', '-no6', '-rfbport', '5900', '-nopw', '-forever',
                         '-shared', '-noxdamage', '-repeat', '-nosel', '-quiet')
        sandbox = ['--no-sandbox'] if not self.config and os.environ.get('POC_ALLOW_UNSANDBOXED') == '1' else []
        # Closed local port discards HTTP(S); managed policy allows only fixture.html.
        # This is isolation for a fictitious page, never a provider proxy.
        network = (['--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222'] if self.config else
                   ['--host-resolver-rules=MAP * ~NOTFOUND', '--proxy-server=http://127.0.0.1:9', '--proxy-bypass-list=<-loopback>'])
        await self.spawn('chromium', *sandbox, '--no-first-run', '--no-default-browser-check',
                         '--disable-background-networking', '--disable-component-update',
                         '--disable-sync', '--disable-extensions', '--disable-gpu',
                         '--disable-dev-shm-usage', '--noerrdialogs', '--kiosk',
                         *network,
                         '--user-data-dir=' + self.directory.name + '/profile',
                         '--window-size=320,640', '--window-position=0,0',
                         '--app=' + ('about:blank' if self.config else 'file:///opt/poc/fixture.html'))
        for _ in range(150):
            if not self.alive():
                raise RuntimeError('BROWSER_UNAVAILABLE')
            try:
                reader, writer = await asyncio.open_connection('127.0.0.1', 5900)
                writer.close()
                await writer.wait_closed()
                await asyncio.sleep(.5)
                if not self.alive():
                    raise RuntimeError('BROWSER_UNAVAILABLE')
                if self.config:
                    self.cdp = CDP(self.config)
                    try:
                        await self.cdp.start()
                    except RecoveryError as error:
                        self.failure = error.code
                        raise
                return
            except OSError:
                await asyncio.sleep(.1)
        raise RuntimeError('BROWSER_UNAVAILABLE')

    def alive(self):
        return bool(self.processes) and all(p.returncode is None for p in self.processes)

    @staticmethod
    def oom_count():
        try:
            lines = Path('/sys/fs/cgroup/memory.events').read_text().splitlines()
            return int(next(line.split()[1] for line in lines if line.startswith('oom_kill ')))
        except (OSError, ValueError, StopIteration):
            return 0

    def error_code(self):
        if self.failure:
            return self.failure
        if self.oom_count() > self.oom_before:
            return 'MEMORY_LIMIT_REACHED'
        if self.directory:
            try:
                with open(Path(self.directory.name) / 'process-errors.log', 'rb') as log:
                    errors = log.read(65536).decode('utf-8', errors='replace').lower()
                if any(value in errors for value in ('no usable sandbox', 'failed to move to new namespace', 'sandbox_linux.cc', 'zygote_host_impl_linux.cc')):
                    return 'SANDBOX_UNAVAILABLE'
            except OSError:
                pass
        return 'BROWSER_UNAVAILABLE'

    async def connect(self):
        return await asyncio.open_connection('127.0.0.1', 5900)

    async def stop(self):
        if self.cdp:
            await self.cdp.stop()
            self.cdp = None
        for process in reversed(self.processes):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
        for process in reversed(self.processes):
            with contextlib.suppress(ProcessLookupError):
                try:
                    await asyncio.wait_for(process.wait(), 2)
                except asyncio.TimeoutError:
                    os.killpg(process.pid, signal.SIGKILL)
                    await process.wait()
        self.processes.clear()
        if self.directory:
            self.directory.cleanup()
            self.directory = None


class Gateway:
    def __init__(self, token, origin, factory, lifetime, clock, novnc, relay=None):
        if relay is None and not re.fullmatch(r'[a-fA-F0-9]{64}', token):
            raise ValueError('POC_ACCESS_TOKEN must contain exactly 64 hexadecimal characters')
        parsed = urlsplit(origin)
        if (parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ('', '/') or not parsed.hostname
                or parsed.scheme not in ('http', 'https')
                or (parsed.scheme == 'http' and parsed.hostname not in ('127.0.0.1', 'localhost'))):
            raise ValueError('Set an HTTPS POC_PUBLIC_ORIGIN; HTTP is allowed only on loopback')
        if not 1 <= lifetime <= 600:
            raise ValueError('Session lifetime must not exceed 600 seconds')
        self.token, self.origin = token, origin.rstrip('/')
        self.factory, self.lifetime, self.clock = factory, lifetime, clock
        self.secure = parsed.scheme == 'https'
        self.novnc = Path(novnc).resolve()
        self.lock = asyncio.Lock()
        self.session = None
        self.relay = relay
        self.mode = 'provider' if relay else 'fixture'

    def require_origin(self, request):
        if request.headers.get('Origin') != self.origin:
            raise web.HTTPForbidden(text='ORIGIN_REFUSED')

    def require_session(self, request):
        session = self.session
        supplied = request.cookies.get(COOKIE, '')
        if (not session or self.clock() >= session['deadline']
                or not re.fullmatch(r'[A-Za-z0-9_-]{43}', supplied)
                or not hmac.compare_digest(session['cookie'], supplied)):
            raise web.HTTPUnauthorized(text='SESSION_REQUIRED')
        return session

    def status(self, session):
        return {'mode': self.mode, 'status': session['status'],
                'remaining_seconds': max(0, int(session['deadline'] - self.clock())),
                'error_code': session.get('error_code')}

    async def begin(self, request):
        self.require_origin(request)
        if request.content_type != 'application/json':
            raise web.HTTPUnsupportedMediaType()
        try:
            data = await request.json()
        except (ValueError, UnicodeError):
            raise web.HTTPBadRequest(text='INVALID_REQUEST')
        field = 'ticket' if self.relay else 'token'
        candidate = data.get(field, '') if isinstance(data, dict) else ''
        pattern = r'[A-Za-z0-9_-]{43}' if self.relay else r'[a-fA-F0-9]{64}'
        if (not isinstance(candidate, str) or not re.fullmatch(pattern, candidate)
                or not isinstance(data, dict) or set(data) != {field}
                or (not self.relay and not hmac.compare_digest(candidate, self.token))):
            raise web.HTTPUnauthorized(text='ACCESS_REFUSED')
        async with self.lock:
            if self.session and self.clock() >= self.session['deadline']:
                await self.finish()
            if self.session:
                session = self.require_session(request)
                response = web.json_response(self.status(session))
            else:
                duration = self.lifetime
                if self.relay:
                    try:
                        duration = min(duration, await self.relay.claim(candidate))
                    except RecoveryError as error:
                        return web.json_response({'mode': 'provider', 'status': 'error', 'error_code': error.code}, status=403)
                session = {'cookie': secrets.token_urlsafe(32), 'deadline': self.clock() + duration,
                           'status': 'starting', 'engine': self.factory(), 'ws': None, 'task': None,
                           'monitor': None, 'ticket': candidate if self.relay else None, 'committed': False}
                self.session = session
                session['task'] = asyncio.create_task(self.launch(session))
                response = web.json_response(self.status(session), status=202)
            response.set_cookie(COOKIE, session['cookie'], max_age=self.lifetime,
                                httponly=True, secure=self.secure, samesite='Strict', path='/')
            return response

    async def launch(self, session):
        try:
            await asyncio.wait_for(session['engine'].start(), 90)
            if self.session is session:
                session['status'] = 'ready'
                if self.relay:
                    session['monitor'] = asyncio.create_task(self.recover(session))
        except asyncio.CancelledError:
            raise
        except Exception:
            session['status'] = 'error'
            session['error_code'] = session['engine'].error_code()
            await session['engine'].stop()
            if self.relay:
                await self.relay.abort(session['ticket'], 'LOCAL_BROWSER_UNAVAILABLE')

    async def recover(self, session):
        bundle = None
        try:
            while self.session is session and self.clock() < session['deadline']:
                if await session['engine'].cdp.authenticated():
                    session['status'] = 'verifying'
                    if session['ws'] is not None:
                        await session['ws'].close(code=1000, message=b'VERIFYING_SESSION')
                    bundle = await session['engine'].cdp.capture()
                    # Close all browser processes before sending the capability bundle.
                    await session['engine'].stop()
                    await self.relay.complete(session['ticket'], bundle)
                    bundle = None
                    session['committed'] = True
                    session['ticket'] = None
                    session['status'] = 'connected'
                    return
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            session['status'] = 'error'
            session['error_code'] = error.code if isinstance(error, RecoveryError) else 'REQUEST_FAILED'
            await session['engine'].stop()
            if session['ticket']:
                await self.relay.abort(session['ticket'], 'LOCAL_BROWSER_UNAVAILABLE')
        finally:
            bundle = None

    async def finish(self, code='LOCAL_CANCELED'):
        session, self.session = self.session, None
        if not session:
            return
        if session['task'] and not session['task'].done():
            session['task'].cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await session['task']
        if session.get('monitor') and not session['monitor'].done():
            session['monitor'].cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await session['monitor']
        if session['ws'] is not None:
            await session['ws'].close(code=1000, message=b'SESSION_ENDED')
        await session['engine'].stop()
        if self.relay and session.get('ticket') and not session.get('committed'):
            await self.relay.abort(session['ticket'], code)
            session['ticket'] = None

    async def maintenance(self):
        async with self.lock:
            session = self.session
            if not session:
                return
            if self.clock() >= session['deadline']:
                await self.finish('LOCAL_LOGIN_EXPIRED')
            elif session['status'] == 'ready' and not session['engine'].alive():
                session['status'] = 'error'
                session['error_code'] = session['engine'].error_code()
                if session['ws'] is not None:
                    await session['ws'].close(code=1011, message=b'BROWSER_UNAVAILABLE')
                await session['engine'].stop()
                if self.relay and session.get('ticket'):
                    await self.relay.abort(session['ticket'], 'LOCAL_BROWSER_UNAVAILABLE')


@web.middleware
async def headers(request, handler):
    try:
        response = await handler(request)
    except web.HTTPException as error:
        response = error
    websocket_origin = request.app[STATE].origin.replace('https://', 'wss://', 1).replace('http://', 'ws://', 1)
    response.headers.update({'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            f"img-src 'self' data:; connect-src 'self' {websocket_origin}; frame-src 'self'; frame-ancestors 'self'; "
            "object-src 'none'; base-uri 'none'; form-action 'none'",
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), clipboard-read=(), clipboard-write=()'})
    return response


async def status(request):
    gateway = request.app[STATE]
    return web.json_response(gateway.status(gateway.require_session(request)))


async def metrics(request):
    gateway = request.app[STATE]
    session = gateway.require_session(request)
    return web.json_response({**gateway.status(session), 'memory': snapshot()})


async def close(request):
    gateway = request.app[STATE]
    gateway.require_origin(request)
    async with gateway.lock:
        gateway.require_session(request)
        await gateway.finish()
    response = web.json_response({'status': 'closed'})
    response.del_cookie(COOKIE, path='/')
    return response


async def static(request):
    gateway = request.app[STATE]
    gateway.require_session(request)
    relative = request.match_info['path']
    path = (gateway.novnc / relative).resolve()
    if not path.is_relative_to(gateway.novnc) or not path.is_file():
        raise web.HTTPNotFound()
    if relative == 'vnc.html':
        html = path.read_text(encoding='utf-8')
        # Preserve official touch keyboard; clipboard is disabled in x11vnc too.
        html = html.replace('</head>', '<style>#noVNC_clipboard_button,#noVNC_settings_button'
                            '{display:none!important}</style></head>')
        return web.Response(text=html, content_type='text/html')
    return web.FileResponse(path, headers={'Content-Type': mimetypes.guess_type(path.name)[0] or 'application/octet-stream'})


async def websocket(request):
    gateway = request.app[STATE]
    gateway.require_origin(request)
    async with gateway.lock:
        session = gateway.require_session(request)
        if session['status'] != 'ready':
            raise web.HTTPConflict(text='BROWSER_NOT_READY')
        if session['ws'] is not None:
            raise web.HTTPConflict(text='VIEW_ALREADY_OPEN')
        try:
            reader, writer = await asyncio.wait_for(session['engine'].connect(), 3)
        except Exception:
            raise web.HTTPServiceUnavailable(text='BROWSER_UNAVAILABLE')
        ws = web.WebSocketResponse(protocols=('binary',), max_msg_size=1024 * 1024, heartbeat=20)
        try:
            await ws.prepare(request)
        except Exception:
            writer.close()
            raise
        session['ws'] = ws

    async def incoming():
        async for message in ws:
            if message.type == WSMsgType.BINARY:
                writer.write(message.data)
                await writer.drain()
            elif message.type == WSMsgType.TEXT:
                await ws.close(code=1003, message=b'BINARY_REQUIRED')
                break

    async def outgoing():
        while not ws.closed:
            data = await reader.read(65536)
            if not data:
                break
            await ws.send_bytes(data)

    tasks = [asyncio.create_task(incoming()), asyncio.create_task(outgoing())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        await ws.close()
        if session['ws'] is ws:
            session['ws'] = None
    return ws


async def lifecycle(app):
    gateway = app[STATE]
    async def reap():
        while True:
            await asyncio.sleep(1)
            await gateway.maintenance()
    task = asyncio.create_task(reap())
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    async with gateway.lock:
        await gateway.finish()


def create_app(token, origin, factory=Browser, lifetime=600, clock=time.monotonic,
               novnc='/usr/share/novnc', relay=None):
    app = web.Application(middlewares=[headers], client_max_size=2048)
    app[STATE] = Gateway(token, origin, factory, lifetime, clock, novnc, relay=relay)
    async def health(request):
        return web.json_response({'ok': True, 'mode': 'human-recovery' if relay else 'fixture-only'})
    async def home(request):
        return web.FileResponse(ROOT / 'index.html')
    async def client(request):
        return web.FileResponse(ROOT / 'client.js', headers={'Content-Type': 'text/javascript'})
    app.add_routes([web.get('/health', health), web.get('/', home), web.get('/client.js', client),
                    web.post('/session', app[STATE].begin), web.get('/status', status),
                    web.get('/metrics', metrics), web.post('/close', close),
                    web.get('/websockify', websocket), web.get('/novnc/{path:.*}', static)])
    app.cleanup_ctx.append(lifecycle)
    return app


if __name__ == '__main__':
    try:
        port = int(os.environ.get('PORT', '10000'))
        if not 1024 <= port <= 65535:
            raise ValueError('Invalid PORT')
        mode = os.environ.get('RECOVERY_MODE', 'fixture')
        if mode not in ('fixture', 'provider'):
            raise ValueError('Invalid mode')
        config = Configuration(os.environ) if mode == 'provider' else None
        if config:
            configure_policy(config)
        app = create_app(os.environ.get('POC_ACCESS_TOKEN', ''),
                         os.environ.get('POC_PUBLIC_ORIGIN') or os.environ.get('RENDER_EXTERNAL_URL', ''),
                         lifetime=int(os.environ.get('POC_SECONDS', '600')),
                         factory=(lambda: Browser(config)) if config else Browser,
                         relay=Relay(config) if config else None)
    except (ValueError, RecoveryError, OSError):
        raise SystemExit('FIXTURE_CONFIGURATION_REQUIRED: token, HTTPS origin, port or duration invalid')
    web.run_app(app, host='0.0.0.0', port=port, access_log=None, print=None)
