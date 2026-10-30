"""Generic authenticated process gateway; private task code is never served here."""
import asyncio
import contextlib
import hashlib
import hmac
import json
import os
import re
import signal
from pathlib import Path

from aiohttp import web

UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
CODE = re.compile(r'[A-Z][A-Z0-9_]{0,99}')
FINAL_STATUSES = {'submitted', 'report_pending', 'report_applied', 'failed',
                  'idle', 'report_settlement_uncertain', 'import_reconciled'}


def owned_browser_groups(run_id, proc_root=Path('/proc'), uid=None):
    """Find only this task's private profile, including detached/orphan browsers."""
    uid = os.getuid() if uid is None else uid
    profile = re.compile(rb'--user-data-dir=/tmp/private-task-' + run_id.encode() + rb'-[A-Za-z0-9_-]{1,64}/profile')
    groups = set()
    for directory in proc_root.iterdir():
        if not directory.name.isdigit():
            continue
        try:
            if directory.stat().st_uid != uid:
                continue
            arguments = (directory / 'cmdline').read_bytes().split(b'\0')
            if not any(profile.fullmatch(argument) for argument in arguments):
                continue
            # comm may contain spaces or parentheses; fields follow its last ).
            stat = (directory / 'stat').read_text()
            group = int(stat[stat.rfind(')') + 1:].split()[2])
            if group > 1 and group != os.getpgrp():
                groups.add(group)
        except (OSError, ValueError, IndexError):
            continue
    return groups


class Automation:
    def __init__(self, gateway, key='', spawn=asyncio.create_subprocess_exec,
                 timeout=205, runner='/opt/poc/runner-loader.mjs'):
        if key and not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', key):
            raise ValueError('Invalid private task key')
        self.gateway, self.key, self.spawn = gateway, key, spawn
        self.timeout, self.runner = timeout, runner
        self.records, self.active_run, self.blocked = {}, None, False

    @property
    def busy(self):
        return self.active_run is not None or self.blocked

    def authorize(self, request):
        if not self.key:
            raise web.HTTPNotFound()
        supplied = request.headers.get('Authorization', '')
        if len(supplied) > 200 or not hmac.compare_digest(supplied.encode(), ('Bearer ' + self.key).encode()):
            raise web.HTTPUnauthorized(text='ACCESS_REFUSED')
        # This route is server-to-server and is never a browser control surface.
        if request.headers.get('Origin'):
            raise web.HTTPForbidden(text='ORIGIN_REFUSED')

    async def body(self, request, fields):
        self.authorize(request)
        if request.content_type != 'application/json':
            raise web.HTTPUnsupportedMediaType()
        try:
            value = await request.json()
        except (ValueError, UnicodeError):
            raise web.HTTPBadRequest(text='INVALID_REQUEST') from None
        if not isinstance(value, dict) or not set(value).issubset(fields):
            raise web.HTTPBadRequest(text='INVALID_REQUEST')
        if not isinstance(value.get('run_id'), str) or not UUID.fullmatch(value['run_id']):
            raise web.HTTPBadRequest(text='INVALID_REQUEST')
        return value

    @staticmethod
    def public(record):
        result = {'run_id': record['run_id'], 'status': record['status']}
        if record.get('code'):
            result['code'] = record['code']
        return result

    async def begin(self, request):
        data = await self.body(request, {'run_id', 'lease_token', 'mode'})
        token, mode = data.get('lease_token'), data.get('mode', 'send')
        if not isinstance(token, str) or not UUID.fullmatch(token) or mode not in ('send', 'report', 'import_reconcile'):
            raise web.HTTPBadRequest(text='INVALID_REQUEST')
        digest = hashlib.sha256(token.encode()).hexdigest()
        async with self.gateway.lock:
            previous = self.records.get(data['run_id'])
            if previous:
                if previous['mode'] != mode or not hmac.compare_digest(previous['lease_hash'], digest):
                    raise web.HTTPConflict(text='RUN_BINDING_MISMATCH')
                return web.json_response(self.public(previous), status=202 if previous['status'] in ('starting', 'running') else 200)
            if self.busy or len(self.records) >= 128:
                raise web.HTTPConflict(text='AUTOMATION_BUSY')
            session = self.gateway.session
            if session and self.gateway.clock() >= session['deadline']:
                try:
                    await asyncio.wait_for(self.gateway.finish('LOCAL_LOGIN_EXPIRED'), 15)
                except Exception:
                    self.blocked = True
                    raise web.HTTPServiceUnavailable(text='BROWSER_CLOSE_UNCERTAIN') from None
                session = None
            if session and self.gateway.relay and session['status'] in ('starting', 'ready', 'verifying'):
                raise web.HTTPConflict(text='HUMAN_RECOVERY_BUSY')
            if session:
                try:
                    await asyncio.wait_for(self.gateway.finish(), 15)
                except Exception:
                    self.blocked = True
                    raise web.HTTPServiceUnavailable(text='BROWSER_CLOSE_UNCERTAIN') from None
            record = {'run_id': data['run_id'], 'lease_hash': digest, 'mode': mode,
                      'status': 'starting', 'task': None, 'process': None}
            self.records[data['run_id']] = record
            self.active_run = data['run_id']
            record['task'] = asyncio.create_task(self.execute(record, token))
            return web.json_response(self.public(record), status=202)

    async def status(self, request):
        data = await self.body(request, {'run_id'})
        record = self.records.get(data['run_id'])
        if not record:
            raise web.HTTPNotFound(text='RUN_UNKNOWN')
        return web.json_response(self.public(record))

    @staticmethod
    async def output(reader):
        content = bytearray()
        while True:
            block = await reader.read(1024)
            if not block:
                return bytes(content)
            content.extend(block)
            if len(content) > 4096:
                raise ValueError('OUTPUT_LIMIT')

    async def kill(self, process, run_id):
        # A new session makes the loader and its Chromium children one owned
        # process group. Also remove stragglers after a normal loader exit.
        if process is None:
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        # Puppeteer normally detaches Chromium into a separate process group.
        # Its exact per-run profile still identifies it after orphan adoption.
        for group in owned_browser_groups(run_id):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(group, signal.SIGKILL)
        if process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), 3)
            except asyncio.TimeoutError:
                self.blocked = True

    async def execute(self, record, token):
        process = None
        deadline = asyncio.get_running_loop().time() + self.timeout
        def remaining():
            return max(.001, deadline - asyncio.get_running_loop().time())
        try:
            env = {name: os.environ[name] for name in ('PATH', 'HOME', 'LANG', 'NODE_PATH',
                   'CF_ORIGIN', 'HOSTED_RUNNER_KEY', 'HOSTED_BUNDLE_SHA256') if name in os.environ}
            # Key is inherited only by the generic server loader. It must give
            # Chromium its own restricted environment, without server secrets.
            env['HOSTED_RUNNER_KEY'] = self.key
            process = await asyncio.wait_for(self.spawn('/usr/local/bin/node', self.runner,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, env=env, cwd='/opt/poc',
                start_new_session=True), min(15, remaining()))
            record['process'] = process
            record['status'] = 'running'
            payload = json.dumps({'run_id': record['run_id'], 'lease_token': token,
                                  'mode': record['mode']}, separators=(',', ':')).encode()
            token = None
            process.stdin.write(payload)
            payload = None
            await asyncio.wait_for(process.stdin.drain(), min(5, remaining()))
            process.stdin.close()
            values = await asyncio.wait_for(asyncio.gather(process.wait(), self.output(process.stdout)), remaining())
            code, raw = values
            result = json.loads(raw)
            raw = None
            if not isinstance(result, dict) or result.get('status') not in FINAL_STATUSES:
                raise ValueError('INVALID_RESULT')
            if code != 0 and result['status'] != 'failed':
                raise ValueError('PROCESS_FAILED')
            record['status'] = result['status']
            value = result.get('code')
            if isinstance(value, str) and CODE.fullmatch(value):
                record['code'] = value
        except asyncio.CancelledError:
            record.update(status='failed', code='HOSTED_RUNNER_STOPPED')
            raise
        except asyncio.TimeoutError:
            record.update(status='failed', code='HOSTED_RUNNER_TIMEOUT')
        except Exception:
            record.update(status='failed', code='HOSTED_RUNNER_FAILED')
        finally:
            token = None
            try:
                await self.kill(process, record['run_id'])
            except Exception:
                self.blocked = True
                record.update(status='failed', code='BROWSER_CLOSE_UNCERTAIN')
            record['process'] = None
            self.active_run = None

    async def close(self):
        tasks = [record['task'] for record in self.records.values()
                 if record.get('task') and not record['task'].done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
