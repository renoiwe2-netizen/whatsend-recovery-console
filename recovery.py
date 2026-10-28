"""Human recovery; optional private prefill, never automatic submission."""
import asyncio
import contextlib
from datetime import datetime, timezone
import json
import os
import time
from pathlib import Path
import re
from urllib.parse import urlsplit, unquote

import aiohttp

SAFE_CODES = {'REQUEST_FAILED', 'SESSION_EXPIRED', 'SESSION_CANCELED', 'SESSION_BUSY',
              'CAPTCHA_REQUIRED', 'BROWSER_UNAVAILABLE', 'SANDBOX_UNAVAILABLE',
              'MEMORY_LIMIT_REACHED', 'CONFIGURATION_REQUIRED', 'ACCESS_REFUSED'}


PREFILL_FUNCTION = r'''function(origin, path, action, formSelector, userSelector, passwordSelector, username, password) {
  const form = this;
  if (location.origin !== origin || location.pathname !== path || location.search || location.hash ||
      !(form instanceof HTMLFormElement) || !form.isConnected || form.ownerDocument !== document ||
      document.querySelectorAll(formSelector).length !== 1 || document.querySelector(formSelector) !== form ||
      form.method.toLowerCase() !== 'post') return false;
  const target = new URL(form.action, location.href);
  if (target.origin !== origin || target.pathname !== action || target.search || target.hash) return false;
  const users = form.querySelectorAll(userSelector), passwords = form.querySelectorAll(passwordSelector);
  if (users.length !== 1 || passwords.length !== 1) return false;
  const user = users[0], pass = passwords[0];
  const writable = field => field instanceof HTMLInputElement && field.form === form &&
    field.isConnected && !field.disabled && !field.readOnly && field.getClientRects().length > 0 &&
    getComputedStyle(field).visibility === 'visible' && field.value === '';
  if (user === pass || !writable(user) || !writable(pass) ||
      !['text', 'email'].includes(user.type) || pass.type !== 'password') return false;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  setter.call(user, username);
  setter.call(pass, password);
  // Deliberately no input/change/keyboard event, click, submit, or token access.
  return true;
}'''


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
        self.prefill_enabled = env.get('PROVIDER_PREFILL_ENABLED') == '1'
        self.username_selector = env.get('PROVIDER_USERNAME_SELECTOR', 'input[name="username"]')
        self.password_selector = env.get('PROVIDER_PASSWORD_SELECTOR', 'input[name="password"]')
        if self.prefill_enabled and any(not isinstance(value, str) or not re.fullmatch(
                r'input\[(?:name|id)="[A-Za-z][A-Za-z0-9_-]{0,63}"\]', value)
                for value in (self.username_selector, self.password_selector)):
            raise RecoveryError('CONFIGURATION_REQUIRED')
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
        request_headers = {'Content-Type': 'application/json'}
        relay_key = os.environ.get('RECOVERY_RELAY_KEY', '') if action == 'claim' and self.config.prefill_enabled else ''
        if relay_key:
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}', relay_key):
                raise RecoveryError('CONFIGURATION_REQUIRED')
            request_headers['X-Recovery-Relay-Key'] = relay_key
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=40)) as client:
                async with client.post(self.config.helper, data=body, headers=request_headers,
                                       allow_redirects=False) as response:
                    raw = bytearray()
                    async for chunk in response.content.iter_chunked(1024):
                        raw.extend(chunk)
                        if len(raw) > (8192 if relay_key else 2048):
                            raise RecoveryError()
                    result = json.loads(raw)
                    if response.status >= 300:
                        raise RecoveryError(result.get('code', 'REQUEST_FAILED') if isinstance(result, dict) else 'REQUEST_FAILED')
            if not isinstance(result, dict) or result.get('ok') is not True:
                raise RecoveryError(result.get('code', 'REQUEST_FAILED') if isinstance(result, dict) else 'REQUEST_FAILED')
            if result.get('status') not in ('starting', 'connected', 'canceled'):
                raise RecoveryError()
            if 'private_credentials' in result and not relay_key:
                raise RecoveryError('ACCESS_REFUSED')
            return result
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            raise RecoveryError() from None
        finally:
            request_headers.clear()
            relay_key = None

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
        credentials = result.pop('private_credentials', None)
        if credentials is not None:
            if (not self.config.prefill_enabled or not isinstance(credentials, dict) or
                    set(credentials) != {'username', 'password'} or
                    not isinstance(credentials['username'], str) or not 1 <= len(credentials['username']) <= 320 or
                    not isinstance(credentials['password'], str) or not 1 <= len(credentials['password']) <= 4096):
                raise RecoveryError('ACCESS_REFUSED')
        return min(seconds, 600), credentials

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
    """Ordinary debugging transport. Optional prefill; no submit or CAPTCHA access."""
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
        self.prefill_attempted = False
        self.prefill_state = 'disabled'
        self.verification = {'sdk': False, 'response_present': False}
        self.verification_changes = 0
        self.blocked_resources = []
        self.verification_ready_at = None

    async def start(self, prefill_credentials=None):
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
        await self.open_login(prefill_credentials)

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

    async def open_login(self, prefill_credentials=None):
        self.phase = 'navigate_login'
        self.prefill_attempted = False
        self.verification_ready_at = None
        self.verification = {'sdk': False, 'response_present': False}
        self.verification_changes = 0
        await self.navigate(self.config.login)
        await self.position_login_form()
        await self.prefill_login(prefill_credentials)
        if self.config.ready:
            self.phase = 'native_verification'
            # Observe the provider's own result only. Never execute verification
            # code, extract/inject its token, or submit the login form.
            for _ in range(40):
                await self.authenticated()
                if self.verification['response_present']:
                    break
                await asyncio.sleep(1)
        # Native verification may legitimately run only during the person's
        # submit. Show the guarded page; never inspect or execute its token.
        self.phase = 'ready'

    async def prefill_login(self, credentials=None):
        if self.prefill_attempted or not self.config.prefill_enabled:
            return
        # One attempt before the viewer opens, never after a person's edits or
        # failed login. Secrets arrive through the private server claim only,
        # not Render credential env, Configuration/CDP or Chrome environment.
        # Drop these temporary Python references finally;
        # Python strings cannot guarantee zeroisation of allocator memory.
        self.prefill_attempted = True
        self.prefill_state = 'skipped'
        source = credentials if isinstance(credentials, dict) else {}
        username = source.get('username', '')
        password = source.get('password', '')
        parameters = None
        try:
            if (not isinstance(username, str) or not isinstance(password, str) or
                    not 1 <= len(username) <= 320 or not 1 <= len(password) <= 4096 or
                    any(char in username + password for char in ('\0', '\r', '\n'))):
                self.prefill_state = 'configuration_missing'
                return
            # Obtain a remote form object only at the expected document. If the
            # page navigates afterwards, the object becomes invalid; the atomic
            # function below also rechecks every boundary before writing.
            expression = ('(()=>{if(location.origin!==' + json.dumps(self.config.origin) +
                '||location.pathname!==' + json.dumps(self.config.login) +
                '||location.search||location.hash)return null;const f=document.querySelectorAll(' +
                json.dumps(self.config.form) + ');return f.length===1?f[0]:null;})()')
            candidate = await self.command('Runtime.evaluate', {'expression': expression,
                'objectGroup': 'private-prefill', 'returnByValue': False, 'silent': True}, self.primary)
            object_id = candidate.get('result', {}).get('objectId')
            if candidate.get('exceptionDetails') or not isinstance(object_id, str):
                return
            parameters = {'objectId': object_id, 'functionDeclaration': PREFILL_FUNCTION,
                'arguments': [{'value': value} for value in (self.config.origin, self.config.login,
                    self.config.submit, self.config.form, self.config.username_selector,
                    self.config.password_selector, username, password)], 'returnByValue': True, 'silent': True}
            result = await self.command('Runtime.callFunctionOn', parameters, self.primary)
            if not result.get('exceptionDetails') and result.get('result', {}).get('value') is True:
                self.prefill_state = 'filled'
        finally:
            if parameters:
                parameters['arguments'].clear()
            username = password = None
            with contextlib.suppress(Exception):
                await self.command('Runtime.releaseObjectGroup', {'objectGroup': 'private-prefill'}, self.primary)

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
                elif data.get('method') in ('Target.attachedToTarget', 'Fetch.requestPaused', 'Network.loadingFailed', 'Runtime.exceptionThrown', 'Runtime.consoleAPICalled'):
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
            if event['method'] in ('Runtime.exceptionThrown', 'Runtime.consoleAPICalled'):
                detail = params.get('exceptionDetails', {}).get('exception', {}).get('description', '')
                args = params.get('args', [])
                first = args[0].get('value', '') if args else ''
                if 'grecaptcha is not defined' in str(detail):
                    print(json.dumps({'native_verification_error': 'SDK_NOT_AVAILABLE'}), flush=True)
                elif isinstance(first, str) and first.startswith('reCAPTCHA failed:'):
                    print(json.dumps({'native_verification_error': 'NATIVE_EXECUTION_FAILED'}), flush=True)
                return
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
                    await self.command('Runtime.enable', session=sid)
                self.sessions[sid] = target['targetId']
                await self.command('Runtime.runIfWaitingForDebugger', session=sid)
                if sid == self.primary:
                    self.ready.set()
            else:
                request = params['request']
                allowed = self.config.permits(request.get('url'), request.get('method'), params.get('resourceType'))
                if not allowed and len(self.blocked_resources) < 12:
                    # No query, path, body, form value or token in diagnostics.
                    host = urlsplit(request.get('url', '')).hostname or ''
                    kind = params.get('resourceType', '')
                    if re.fullmatch(r'[a-zA-Z0-9.-]{1,180}', host) and kind in ('Document', 'Script', 'XHR', 'Fetch', 'Other'):
                        item = {'host': host, 'type': kind}
                        if item not in self.blocked_resources:
                            self.blocked_resources.append(item)
                            print(json.dumps({'blocked_login_resource': item}), flush=True)
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
        expression = '(()=>{const own=location.origin===' + json.dumps(self.config.origin) + ';return {authenticated:own&&document.querySelectorAll(' + json.dumps(self.config.marker) + ').length===1&&!document.querySelector(' + json.dumps(self.config.form) + '),login:own&&location.pathname===' + json.dumps(self.config.login) + ',sdk:typeof grecaptcha!=="undefined"&&typeof grecaptcha.ready==="function",response_present:own&&Boolean(document.querySelector("input#g-recaptcha-response")?.value)};})()'
        result = await self.evaluate(expression)
        if isinstance(result, dict):
            if result.get('login') and self.verification_changes < 6:
                facts = {key: result.get(key) is True for key in ('sdk', 'response_present')}
                if facts != self.verification or self.verification_changes == 0:
                    self.verification = facts
                    self.verification_changes += 1
                    print(json.dumps({'native_verification': facts}), flush=True)
                if facts['response_present'] and self.verification_ready_at is None:
                    self.verification_ready_at = time.monotonic()
            return result.get('authenticated') is True
        return result is True

    def verification_status(self):
        if not self.config.ready:
            return 'not_required'
        if not self.verification['response_present']:
            return 'waiting'
        return 'ready' if self.verification_ready_at is not None and time.monotonic()-self.verification_ready_at < 90 else 'expired'

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
