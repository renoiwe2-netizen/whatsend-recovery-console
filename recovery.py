"""Human-only recovery adapter. Destinations/selectors are private server config."""
import asyncio
import contextlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit, unquote

import aiohttp

SAFE_CODES = {'REQUEST_FAILED', 'SESSION_EXPIRED', 'SESSION_CANCELED', 'SESSION_BUSY',
              'CAPTCHA_REQUIRED', 'BROWSER_UNAVAILABLE', 'SANDBOX_UNAVAILABLE',
              'MEMORY_LIMIT_REACHED', 'CONFIGURATION_REQUIRED', 'ACCESS_REFUSED'}


class RecoveryError(Exception):
    def __init__(self, code='REQUEST_FAILED'):
        self.code = code if code in SAFE_CODES else 'REQUEST_FAILED'
        super().__init__(self.code)


def exact_origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.port not in (None, 443)):
        raise RecoveryError('CONFIGURATION_REQUIRED')
    return 'https://' + parsed.hostname


def exact_path(value):
    if (not isinstance(value, str) or not value.startswith('/') or value.startswith('//')
            or len(value) > 250 or any(char in value for char in ('?', '#', '\\', '%', '\r', '\n'))
            or '..' in value.split('/')):
        raise RecoveryError('CONFIGURATION_REQUIRED')
    return value


class Configuration:
    def __init__(self, env):
        self.origin = exact_origin(env.get('PROVIDER_ORIGIN', ''))
        self.host = urlsplit(self.origin).hostname
        helper = env.get('RECOVERY_HELPER_URL', '')
        parsed = urlsplit(helper)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.port not in (None, 443)
                or parsed.path != '/functions/v1/provider-recovery-helper'):
            raise RecoveryError('CONFIGURATION_REQUIRED')
        self.helper = helper
        self.login = exact_path(env.get('PROVIDER_LOGIN_PATH', '/login'))
        self.submit = exact_path(env.get('PROVIDER_LOGIN_SUBMIT_PATH', '/auth/login'))
        self.landing = exact_path(env.get('PROVIDER_LANDING_PATH', ''))
        self.profile = exact_path(env.get('PROVIDER_PROFILE_PATH', ''))
        self.marker = env.get('PROVIDER_AUTH_MARKER', '')
        self.form = env.get('PROVIDER_LOGIN_FORM', '')
        self.ready = env.get('PROVIDER_NATIVE_READY_SELECTOR', '')
        if any(not value or len(value) > 250 for value in (self.marker, self.form)):
            raise RecoveryError('CONFIGURATION_REQUIRED')
        try:
            self.documents = {self.login, self.landing, self.profile}
            self.documents.update(exact_path(value) for value in json.loads(env.get('PROVIDER_READ_PATHS', '[]')))
            self.assets = tuple(exact_path(value) for value in json.loads(env.get('PROVIDER_ASSET_PREFIXES', '[]')))
            self.challenge_origins = {exact_origin(value) for value in json.loads(env.get('PROVIDER_CHALLENGE_ORIGINS', '[]'))}
            self.static_origins = {exact_origin(value) for value in json.loads(env.get('PROVIDER_STATIC_ORIGINS', '[]'))}
        except (TypeError, ValueError):
            raise RecoveryError('CONFIGURATION_REQUIRED') from None
        if any(value == '/' or not value.endswith('/') for value in self.assets):
            raise RecoveryError('CONFIGURATION_REQUIRED')
        if len(self.documents) > 8 or len(self.assets) > 12 or len(self.challenge_origins | self.static_origins) > 12:
            raise RecoveryError('CONFIGURATION_REQUIRED')

    def permits(self, url, method, resource):
        """Fail closed: no campaign pages or actions; only normal auth and assets."""
        try:
            parsed = urlsplit(url)
            if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port not in (None, 443):
                return False
            origin = 'https://' + (parsed.hostname or '')
            path = parsed.path
            if unquote(path) != path or '\\' in path or '..' in path.split('/'):
                return False
            if origin == self.origin:
                if method == 'POST':
                    return path == self.submit and resource in ('XHR', 'Fetch', 'Document')
                if method != 'GET':
                    return False
                if path in self.documents:
                    return not parsed.query
                return (resource in ('Script', 'Stylesheet', 'Image', 'Font', 'Media')
                        and any(path.startswith(prefix) for prefix in self.assets))
            if origin in self.challenge_origins:
                return method in ('GET', 'POST') and path.startswith('/recaptcha/')
            if origin in self.static_origins:
                return method == 'GET' and resource in ('Script', 'Stylesheet', 'Image', 'Font')
            return False
        except (ValueError, TypeError):
            return False

    def worker_network_guard(self):
        # Dedicated workers do not expose Fetch. Network's ordered URLPattern
        # rules run inside their renderer; deny the provider even if misconfigured
        # among external origins. Legacy engines ignore urlPatterns but still
        # apply urls=['*'], so unsupported versions remain closed.
        patterns = [{'urlPattern': self.origin + '/*', 'block': True}]
        patterns.extend({'urlPattern': origin + '/recaptcha/*', 'block': False}
                        for origin in sorted(self.challenge_origins - {self.origin}))
        patterns.extend({'urlPattern': origin + '/*', 'block': False}
                        for origin in sorted(self.static_origins - self.challenge_origins - {self.origin}))
        patterns.append({'urlPattern': '*://*:*/*', 'block': True})
        return {'urlPatterns': patterns, 'urls': ['*']}


class Relay:
    def __init__(self, config):
        self.config = config

    async def call(self, action, ticket, **extra):
        if not isinstance(ticket, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', ticket):
            raise RecoveryError('ACCESS_REFUSED')
        body = json.dumps({'action': action, 'ticket': ticket, **extra}, separators=(',', ':'))
        if len(body.encode()) > 32768:
            raise RecoveryError()
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=40)) as client:
                async with client.post(self.config.helper, data=body, headers={'Content-Type': 'application/json'},
                                       allow_redirects=False) as response:
                    raw = bytearray()
                    async for chunk in response.content.iter_chunked(1024):
                        raw.extend(chunk)
                        if len(raw) > 2048:
                            raise RecoveryError()
                    result = json.loads(raw)
                    if response.status >= 300:
                        raise RecoveryError(result.get('code', 'REQUEST_FAILED') if isinstance(result, dict) else 'REQUEST_FAILED')
            if not isinstance(result, dict) or result.get('ok') is not True:
                raise RecoveryError(result.get('code', 'REQUEST_FAILED') if isinstance(result, dict) else 'REQUEST_FAILED')
            if result.get('status') not in ('starting', 'connected', 'canceled'):
                raise RecoveryError()
            return result
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            raise RecoveryError() from None

    async def claim(self, ticket):
        result = await self.call('claim', ticket)
        if result.get('status') != 'starting':
            raise RecoveryError()
        try:
            seconds = datetime.fromisoformat(result['expires_at'].replace('Z', '+00:00')).timestamp() - datetime.now(timezone.utc).timestamp()
        except (KeyError, ValueError, TypeError):
            raise RecoveryError('SESSION_EXPIRED') from None
        if not 0 < seconds <= 605:
            raise RecoveryError('SESSION_EXPIRED')
        return min(seconds, 600)

    async def complete(self, ticket, session):
        # Exact same capability+bundle on retry; server CAS makes ACK loss idempotent.
        for attempt in range(2):
            try:
                result = await self.call('complete', ticket, session=session)
                if result.get('status') != 'connected':
                    raise RecoveryError()
                return
            except RecoveryError as error:
                if error.code != 'REQUEST_FAILED' or attempt:
                    raise
                await asyncio.sleep(1)

    async def abort(self, ticket, code):
        with contextlib.suppress(RecoveryError):
            await self.call('abort', ticket, code=code)


class CDP:
    """Ordinary debugging transport. No credential writes or CAPTCHA token access."""
    def __init__(self, config):
        self.config = config
        self.client = None
        self.ws = None
        self.reader = None
        self.pending = {}
        self.pending_methods = {}
        self.sequence = 0
        self.handlers = set()
        self.sessions = {}
        self.primary = None
        self.ready = asyncio.Event()
        self.failed = False
        self.phase = 'created'
        self.diagnostic_code = None
        self.browser_product = 'unknown'
        self.worker_sessions = set()
        self.worker_blocked_count = 0
        self.worker_network_failed = False
        self.viewport = {}

    async def start(self):
        self.phase = 'devtools_endpoint'
        self.client = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5))
        url = None
        for _ in range(150):
            try:
                async with self.client.get('http://127.0.0.1:9222/json/version') as response:
                    url = (await response.json())['webSocketDebuggerUrl']
                    parsed = urlsplit(url)
                    if parsed.scheme != 'ws' or parsed.hostname not in ('127.0.0.1', 'localhost') or parsed.port != 9222:
                        self.diagnostic_code = 'CDP_ENDPOINT_REFUSED'
                        raise RecoveryError()
                    break
            except (aiohttp.ClientError, asyncio.TimeoutError, KeyError):
                await asyncio.sleep(.1)
        if not url:
            self.diagnostic_code = 'CDP_ENDPOINT_UNAVAILABLE'
            raise RecoveryError('BROWSER_UNAVAILABLE')
        self.phase = 'devtools_websocket'
        self.ws = await self.client.ws_connect(url, max_msg_size=1048576)
        self.reader = asyncio.create_task(self.receive())
        version = await self.command('Browser.getVersion')
        product = version.get('product', '')
        if isinstance(product, str) and re.fullmatch(r'(?:Chrome|Chromium)/[0-9]{1,4}(?:\.[0-9]{1,6}){1,3}', product):
            self.browser_product = product
        self.phase = 'attach_page'
        await self.command('Target.setAutoAttach', {'autoAttach': True, 'waitForDebuggerOnStart': True, 'flatten': True})
        await asyncio.wait_for(self.ready.wait(), 15)
        if self.failed:
            raise RecoveryError('BROWSER_UNAVAILABLE')
        await self.configure_viewport()
        await self.open_login()

    async def configure_viewport(self):
        """Fit the ordinary desktop page to the actual 320x640 VNC screen."""
        self.phase = 'viewport_config'
        def size(source, width='width', height='height'):
            return {key: value for key, value in [('width', source.get(width)), ('height', source.get(height))]
                    if type(value) in (int, float) and 0 < value <= 16384}
        before = await self.command('Page.getLayoutMetrics', session=self.primary)
        self.viewport['before'] = size(before.get('cssLayoutViewport', {}), 'clientWidth', 'clientHeight')
        window = await self.command('Browser.getWindowForTarget', {'targetId': self.sessions[self.primary]})
        self.viewport['window'] = size(window.get('bounds', {}))
        # No user-agent, touch capability, navigator or page CSS modification.
        # Keep desktop behavior; dimensions match the real Xvfb framebuffer.
        await self.command('Emulation.setDeviceMetricsOverride',
                           {'width': 320, 'height': 640, 'deviceScaleFactor': 1, 'mobile': False,
                            'screenWidth': 320, 'screenHeight': 640}, self.primary)
        after = await self.command('Page.getLayoutMetrics', session=self.primary)
        self.viewport['after'] = size(after.get('cssLayoutViewport', {}), 'clientWidth', 'clientHeight')

    async def open_login(self):
        self.phase = 'navigate_login'
        await self.navigate(self.config.login)
        await self.position_login_form()
        # Native verification may legitimately run only during the person's
        # submit. Show the guarded page; never inspect or execute its token.
        self.phase = 'ready'

    async def position_login_form(self):
        # Native scroll only. Depth 0 avoids retrieving the page content or
        # field attributes; querySelector returns a node id, never values.
        document = await self.command('DOM.getDocument', {'depth': 0}, self.primary)
        root = document.get('root', {}).get('nodeId')
        if type(root) is not int or root <= 0:
            return
        form = await self.command('DOM.querySelector', {'nodeId': root, 'selector': self.config.form}, self.primary)
        node = form.get('nodeId')
        if type(node) is int and node > 0:
            await self.command('DOM.scrollIntoViewIfNeeded', {'nodeId': node}, self.primary)

    async def command(self, method, params=None, session=None):
        if not self.ws or self.ws.closed:
            raise RecoveryError('BROWSER_UNAVAILABLE')
        self.sequence += 1
        ident = self.sequence
        future = asyncio.get_running_loop().create_future()
        self.pending[ident] = future
        self.pending_methods[ident] = method
        message = {'id': ident, 'method': method, 'params': params or {}}
        if session:
            message['sessionId'] = session
        await self.ws.send_json(message)
        try:
            return await asyncio.wait_for(future, 15)
        except asyncio.TimeoutError:
            self.diagnostic_code = self.diagnostic_code or 'CDP_TIMEOUT'
            raise
        finally:
            self.pending.pop(ident, None)
            self.pending_methods.pop(ident, None)

    async def receive(self):
        try:
            async for message in self.ws:
                if message.type != aiohttp.WSMsgType.TEXT:
                    continue
                data = json.loads(message.data)
                if 'id' in data:
                    future = self.pending.get(data['id'])
                    if future and not future.done():
                        if 'error' in data:
                            codes = {'Target.setAutoAttach': 'CDP_ATTACH_REFUSED',
                                     'Fetch.enable': 'CDP_FETCH_GUARD_REFUSED',
                                     'Network.enable': 'CDP_WORKER_NETWORK_REFUSED',
                                     'Network.setBlockedURLs': 'CDP_WORKER_NETWORK_GUARD_REFUSED',
                                     'Network.setBypassServiceWorker': 'CDP_WORKER_GUARD_REFUSED',
                                     'Page.enable': 'CDP_PAGE_REFUSED',
                                     'Runtime.runIfWaitingForDebugger': 'CDP_RESUME_REFUSED',
                                     'Page.navigate': 'CDP_NAVIGATION_REFUSED',
                                     'Page.getLayoutMetrics': 'CDP_VIEWPORT_READ_REFUSED',
                                     'Browser.getWindowForTarget': 'CDP_WINDOW_READ_REFUSED',
                                     'Emulation.setDeviceMetricsOverride': 'CDP_VIEWPORT_REFUSED',
                                     'Runtime.evaluate': 'CDP_READ_REFUSED',
                                     'Network.getCookies': 'CDP_COOKIES_REFUSED'}
                            self.diagnostic_code = self.diagnostic_code or codes.get(self.pending_methods.get(data['id']), 'CDP_PROTOCOL_REFUSED')
                            future.set_exception(RecoveryError('BROWSER_UNAVAILABLE'))
                        else:
                            future.set_result(data.get('result', {}))
                elif data.get('method') in ('Target.attachedToTarget', 'Fetch.requestPaused', 'Network.loadingFailed'):
                    task = asyncio.create_task(self.event(data))
                    self.handlers.add(task)
                    task.add_done_callback(self.handlers.discard)
        finally:
            self.failed = True
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(RecoveryError('BROWSER_UNAVAILABLE'))

    async def event(self, event):
        try:
            params = event['params']
            if event['method'] == 'Network.loadingFailed':
                if event.get('sessionId') in self.worker_sessions:
                    self.worker_network_failed = True
                    if params.get('blockedReason') == 'inspector' or params.get('errorText') == 'net::ERR_BLOCKED_BY_CLIENT':
                        self.worker_blocked_count = min(9999, self.worker_blocked_count + 1)
                return
            if event['method'] == 'Target.attachedToTarget':
                sid = params['sessionId']
                target = params['targetInfo']
                kind = target.get('type')
                worker = kind in ('worker', 'service_worker', 'shared_worker')
                worker_url = target.get('url', '')
                if worker_url.startswith('blob:'):
                    worker_url = worker_url[5:]
                parsed_worker = urlsplit(worker_url)
                worker_origin = 'https://' + (parsed_worker.hostname or '')
                allowed_worker = (worker and parsed_worker.scheme == 'https'
                    and worker_origin in self.config.challenge_origins | self.config.static_origins
                    and not parsed_worker.username and not parsed_worker.password)
                # Workers have Network but may not have Fetch. Install their
                # deny-by-default network rules before resuming native code.
                if (kind not in ('page', 'iframe') and not allowed_worker) or (kind == 'page' and self.primary):
                    await self.command('Target.closeTarget', {'targetId': target['targetId']})
                    return
                if target.get('type') == 'page':
                    self.primary = sid
                if worker:
                    self.worker_sessions.add(sid)
                    await self.command('Network.enable', session=sid)
                    await self.command('Network.setBlockedURLs', self.config.worker_network_guard(), sid)
                else:
                    await self.command('Fetch.enable', {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]}, sid)
                    await self.command('Network.setBypassServiceWorker', {'bypass': True}, sid)
                await self.command('Target.setAutoAttach', {'autoAttach': True, 'waitForDebuggerOnStart': True, 'flatten': True}, sid)
                if target.get('type') == 'page':
                    await self.command('Page.enable', session=sid)
                self.sessions[sid] = target['targetId']
                await self.command('Runtime.runIfWaitingForDebugger', session=sid)
                if sid == self.primary:
                    self.ready.set()
            else:
                request = params['request']
                allowed = self.config.permits(request.get('url'), request.get('method'), params.get('resourceType'))
                await self.command('Fetch.continueRequest' if allowed else 'Fetch.failRequest',
                                   {'requestId': params['requestId'], **({} if allowed else {'errorReason': 'BlockedByClient'})},
                                   event.get('sessionId'))
        except Exception:
            self.failed = True
            self.ready.set()
            if self.ws:
                await self.ws.close()

    async def evaluate(self, expression):
        result = await self.command('Runtime.evaluate', {'expression': expression, 'returnByValue': True}, self.primary)
        if result.get('exceptionDetails'):
            raise RecoveryError()
        return result.get('result', {}).get('value')

    async def navigate(self, path):
        result = await self.command('Page.navigate', {'url': self.config.origin + path}, self.primary)
        if result.get('errorText'):
            error = result.get('errorText')
            self.diagnostic_code = ('NAVIGATION_POLICY_BLOCKED' if error in ('net::ERR_BLOCKED_BY_ADMINISTRATOR', 'net::ERR_BLOCKED_BY_ADMINISTRATOR_POLICY')
                                    else 'NAVIGATION_GUARD_BLOCKED' if error == 'net::ERR_BLOCKED_BY_CLIENT'
                                    else 'NAVIGATION_FAILED')
            raise RecoveryError('BROWSER_UNAVAILABLE')
        for _ in range(60):
            facts = await self.evaluate('({origin:location.origin,path:location.pathname,ready:document.readyState})')
            if facts and facts.get('origin') == self.config.origin and facts.get('path') == path and facts.get('ready') in ('interactive', 'complete'):
                return
            await asyncio.sleep(.25)
        self.diagnostic_code = 'NAVIGATION_NOT_READY'
        raise RecoveryError('BROWSER_UNAVAILABLE')

    async def authenticated(self):
        if self.failed:
            raise RecoveryError('BROWSER_UNAVAILABLE')
        expression = '(location.origin===' + json.dumps(self.config.origin) + ' && document.querySelectorAll(' + json.dumps(self.config.marker) + ').length===1 && !document.querySelector(' + json.dumps(self.config.form) + '))'
        return await self.evaluate(expression) is True

    async def capture(self):
        # Two ordinary GET navigations, never the profile form submit.
        for path in (self.config.landing, self.config.profile):
            await self.navigate(path)
            if not await self.authenticated():
                raise RecoveryError('ACCESS_REFUSED')
        account = await self.evaluate("(()=>{const r={};for(const k of ['username','email']){const e=document.querySelectorAll('input[name=\"'+k+'\"]');if(e.length!==1)return null;r[k]=e[0].value;}return r;})()")
        if not isinstance(account, dict) or any(not isinstance(account.get(k), str) or len(account[k]) > 320 for k in ('username', 'email')):
            raise RecoveryError('ACCESS_REFUSED')
        data = await self.command('Network.getCookies', {'urls': [self.config.origin + '/']}, self.primary)
        cookies = []
        for item in data.get('cookies', []):
            domain = str(item.get('domain', '')).lstrip('.')
            if domain != self.config.host and not ('.' in domain and self.config.host.endswith('.' + domain)):
                continue
            cookies.append({key: value for key, value in item.items() if key in ('name', 'value', 'domain', 'path', 'secure', 'httpOnly', 'sameSite', 'expires')})
        if not 1 <= len(cookies) <= 50:
            raise RecoveryError('ACCESS_REFUSED')
        return {'version': 1, 'account': account, 'cookies': cookies}

    async def stop(self):
        for task in list(self.handlers):
            task.cancel()
        await asyncio.gather(*self.handlers, return_exceptions=True)
        if self.ws:
            await self.ws.close()
        if self.reader:
            self.reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.reader
        if self.client:
            await self.client.close()


def managed_policy(config):
    # Enterprise URL filters are prefixes, not globs. The trailing /* is invalid.
    # A dot before the hostname restricts matches to that exact hostname.
    allowed = ['https://.' + urlsplit(origin).hostname for origin in {config.origin} | config.challenge_origins | config.static_origins]
    return {'URLBlocklist': ['*'], 'URLAllowlist': ['about:blank', *sorted(allowed)],
              'PasswordManagerEnabled': False, 'TranslateEnabled': False, 'SyncDisabled': True, 'BrowserSignin': 0,
              'BrowserGuestModeEnabled': False, 'PrintingEnabled': False, 'DownloadRestrictions': 3}


def configure_policy(config):
    path = Path('/etc/chromium/policies/managed/fixture.json')
    path.write_text(json.dumps(managed_policy(config)), encoding='utf-8')
