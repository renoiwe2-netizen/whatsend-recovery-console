"""Private process gateway tests; fake children and loopback HTTP only."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from aiohttp.test_utils import TestClient, TestServer
from server import create_app, STATE
from automation import owned_browser_groups

KEY = 'a' * 43
TOKEN = 'ab' * 32
ORIGIN = 'https://fixture.example'
RUN = '12345678-1234-4234-8234-123456789abc'
LEASE = '87654321-4321-4321-8321-cba987654321'
OTHER = '22345678-1234-4234-8234-123456789abc'


class Input:
    def __init__(self):
        self.value, self.closed = b'', False
    def write(self, value):
        self.value += value
    async def drain(self):
        pass
    def close(self):
        self.closed = True


class Process:
    def __init__(self):
        self.pid, self.returncode = 99999999, None
        self.stdin, self.stdout = Input(), asyncio.StreamReader()
        self.done = asyncio.get_running_loop().create_future()
    async def wait(self):
        return await asyncio.shield(self.done)
    def finish(self, result=None, code=0):
        if self.returncode is not None:
            return
        self.returncode = code
        if result is not None:
            self.stdout.feed_data(json.dumps(result).encode())
        self.stdout.feed_eof()
        self.done.set_result(code)


class Desktop:
    def __init__(self):
        self.stopped = 0
    async def stop(self):
        self.stopped += 1


class AutomationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.processes, self.calls, self.kills = [], [], []
        async def spawn(*args, **kwargs):
            process = Process()
            self.processes.append(process)
            self.calls.append((args, kwargs))
            return process
        self.spawn = spawn
        self.app = create_app(TOKEN, ORIGIN, automation_key=KEY, automation_spawn=spawn)
        self.gateway = self.app[STATE]
        self.automation = self.gateway.automation
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()
        def kill(pid, sig):
            self.kills.append((pid, sig))
            for process in self.processes:
                if process.pid == pid:
                    process.finish(code=-9)
        self.kill_patch = patch('automation.os.killpg', side_effect=kill, create=True)
        self.signal_patch = patch('automation.signal.SIGKILL', 9, create=True)
        self.groups_patch = patch('automation.owned_browser_groups', return_value=set())
        self.groups_patch.start()
        self.signal_patch.start()
        self.kill_patch.start()
        self.auth = {'Authorization': 'Bearer ' + KEY}

    async def asyncTearDown(self):
        await self.client.close()
        self.kill_patch.stop()
        self.signal_patch.stop()
        self.groups_patch.stop()

    async def begin(self, **overrides):
        data = {'run_id': RUN, 'lease_token': LEASE, **overrides}
        return await self.client.post('/automation/run', headers=self.auth, json=data)

    async def started(self):
        for _ in range(20):
            if self.processes:
                return self.processes[0]
            await asyncio.sleep(0)
        self.fail('Fake child did not start')

    async def finish(self, result=None, code=0):
        process = await self.started()
        process.finish(result or {'status': 'submitted'}, code)
        await self.automation.records[RUN]['task']
        return process

    async def test_auth_shape_and_browser_origin_fail_before_a_process(self):
        for headers, data, status in [
            ({}, {'run_id': RUN, 'lease_token': LEASE}, 401),
            ({**self.auth, 'Origin': ORIGIN}, {'run_id': RUN, 'lease_token': LEASE}, 403),
            (self.auth, {'run_id': RUN, 'lease_token': LEASE, 'url': 'https://private.invalid'}, 400),
            (self.auth, {'run_id': RUN, 'lease_token': 'not-a-lease'}, 400),
            (self.auth, {'run_id': RUN, 'lease_token': LEASE, 'mode': 'other'}, 400),
        ]:
            response = await self.client.post('/automation/run', headers=headers, json=data)
            self.assertEqual(response.status, status)
        self.assertEqual(self.processes, [])
        self.assertEqual((await self.client.get('/health')).status, 200)

    async def test_one_launch_and_idempotent_run_with_sanitized_final_status(self):
        response = await self.begin()
        self.assertEqual(response.status, 202)
        self.assertEqual(await response.json(), {'run_id': RUN, 'status': 'starting'})
        self.assertEqual((await self.begin()).status, 202)
        self.assertEqual((await self.begin(run_id=OTHER)).status, 409)
        self.assertEqual((await self.begin(lease_token=OTHER)).status, 409)
        await self.finish({'status': 'submitted', 'provider_id': 'private-value', 'contacts': ['private']})
        response = await self.begin()
        self.assertEqual(response.status, 200)
        self.assertEqual(await response.json(), {'run_id': RUN, 'status': 'submitted'})
        self.assertEqual(len(self.processes), 1)
        self.assertEqual(len(self.kills), 1)
        response = await self.client.post('/automation/status', headers=self.auth, json={'run_id': RUN})
        self.assertNotIn('private', await response.text())

    async def test_import_reconcile_is_lease_bound_and_returns_only_safe_final_status(self):
        response = await self.begin(mode='import_reconcile')
        self.assertEqual(response.status, 202)
        process = await self.started()
        self.assertEqual(json.loads(process.stdin.value),
                         {'run_id': RUN, 'lease_token': LEASE, 'mode': 'import_reconcile'})
        self.assertEqual((await self.begin(mode='import_reconcile')).status, 202)
        self.assertEqual((await self.begin(mode='send')).status, 409)
        self.assertEqual((await self.begin(mode='import_reconcile', lease_token=OTHER)).status, 409)
        await self.finish({'status': 'import_reconciled', 'code': 'IMPORT_RECONCILED',
                           'contacts': ['private'], 'binding': 'private'})
        response = await self.begin(mode='import_reconcile')
        self.assertEqual(response.status, 200)
        self.assertEqual(await response.json(),
                         {'run_id': RUN, 'status': 'import_reconciled', 'code': 'IMPORT_RECONCILED'})
        self.assertEqual(len(self.processes), 1)
        self.assertFalse(self.automation.busy)

    async def test_invalid_mode_shapes_are_refused_before_a_process(self):
        for mode in ('import', 'IMPORT_RECONCILE', '', None, [], {}, 1):
            with self.subTest(mode=mode):
                self.assertEqual((await self.begin(mode=mode)).status, 400)
        self.assertEqual(self.processes, [])

    async def test_stdin_only_credentials_and_restricted_child_environment(self):
        with patch.dict(os.environ, {'UNRELATED_SECRET': 'do-not-inherit', 'CF_ORIGIN': 'https://relay.example',
                                   'HOSTED_BUNDLE_SHA256': 'b' * 64}):
            await self.begin(mode='report')
            process = await self.started()
        args, options = self.calls[0]
        self.assertEqual(args, ('/usr/local/bin/node', '/opt/poc/runner-loader.mjs'))
        self.assertTrue(options['start_new_session'])
        self.assertNotIn('UNRELATED_SECRET', options['env'])
        self.assertNotIn(LEASE, repr(args) + repr(options))
        self.assertEqual(json.loads(process.stdin.value), {'run_id': RUN, 'lease_token': LEASE, 'mode': 'report'})
        self.assertTrue(process.stdin.closed)
        await self.finish({'status': 'report_pending'})

    async def test_active_human_recovery_refuses_runner_without_closing_it(self):
        desktop = Desktop()
        self.gateway.relay = object()
        self.gateway.session = {'status': 'ready', 'deadline': self.gateway.clock() + 30,
            'engine': desktop, 'task': None, 'monitor': None, 'ws': None, 'ticket': None, '_prefill': None}
        response = await self.begin()
        self.assertEqual(response.status, 409)
        self.assertEqual(await response.text(), 'HUMAN_RECOVERY_BUSY')
        self.assertEqual(desktop.stopped, 0)
        self.assertEqual(self.processes, [])

    async def test_idle_headful_closes_before_runner_and_human_begin_is_blocked(self):
        desktop = Desktop()
        self.gateway.session = {'status': 'connected', 'deadline': self.gateway.clock() + 30,
            'engine': desktop, 'task': None, 'monitor': None, 'ws': None, 'ticket': None, '_prefill': None}
        response = await self.begin()
        self.assertEqual(response.status, 202)
        await self.started()
        self.assertEqual(desktop.stopped, 1)
        self.assertIsNone(self.gateway.session)
        response = await self.client.post('/session', headers={'Origin': ORIGIN}, json={'token': TOKEN})
        self.assertEqual(response.status, 409)
        await self.finish()

    async def test_timeout_kills_owned_group_and_never_restarts_the_run(self):
        self.automation.timeout = .01
        await self.begin()
        await self.automation.records[RUN]['task']
        self.assertEqual(self.automation.public(self.automation.records[RUN]),
                         {'run_id': RUN, 'status': 'failed', 'code': 'HOSTED_RUNNER_TIMEOUT'})
        self.assertEqual(len(self.kills), 1)
        self.assertFalse(self.automation.busy)
        self.assertEqual((await self.begin()).status, 200)
        self.assertEqual(len(self.processes), 1)

    async def test_invalid_or_unbounded_output_is_never_returned(self):
        await self.begin()
        process = await self.started()
        process.stdout.feed_data(b'PRIVATE' * 1000)
        await self.automation.records[RUN]['task']
        record = self.automation.public(self.automation.records[RUN])
        self.assertEqual(record['status'], 'failed')
        self.assertNotIn('PRIVATE', repr(record))
        self.assertEqual(len(self.kills), 1)

    async def test_disabled_routes_do_not_use_desktop_cookie_as_authorization(self):
        self.automation.key = ''
        self.assertEqual((await self.begin()).status, 404)
        self.assertEqual(self.processes, [])

    async def test_uncertain_idle_browser_close_blocks_all_new_browsers(self):
        desktop = Desktop()
        desktop.stop = AsyncMock(side_effect=RuntimeError('private transport data'))
        self.gateway.session = {'status': 'connected', 'deadline': self.gateway.clock() + 30,
            'engine': desktop, 'task': None, 'monitor': None, 'ws': None, 'ticket': None, '_prefill': None}
        response = await self.begin()
        self.assertEqual(response.status, 503)
        self.assertEqual(await response.text(), 'BROWSER_CLOSE_UNCERTAIN')
        self.assertTrue(self.automation.busy)
        self.assertEqual((await self.begin()).status, 409)
        response = await self.client.post('/session', headers={'Origin': ORIGIN}, json={'token': TOKEN})
        self.assertEqual(response.status, 409)
        self.assertEqual(self.processes, [])

    async def test_detached_browser_group_is_killed_after_loader_exit(self):
        self.groups_patch.stop()
        self.groups_patch = patch('automation.owned_browser_groups', return_value={99999998})
        self.groups_patch.start()
        await self.begin()
        await self.finish({'status': 'report_settlement_uncertain', 'code': 'REPORT_COMMIT_UNCERTAIN'})
        self.assertEqual([pid for pid, _ in self.kills], [99999999, 99999998])
        self.assertEqual(self.automation.records[RUN]['status'], 'report_settlement_uncertain')


class ProcessScopeTests(unittest.TestCase):
    def test_proc_scan_matches_only_the_owned_exact_task_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for pid, profile, group in [
                ('201', f'/tmp/private-task-{RUN}-abcdef/profile', 301),
                ('202', f'/tmp/private-task-{OTHER}-abcdef/profile', 302),
                ('203', '/tmp/recovery-private/profile', 303),
                ('204', f'/tmp/private-task-{RUN}-abcdef/profile/other', 304),
            ]:
                directory = root / pid
                directory.mkdir()
                (directory / 'cmdline').write_bytes(b'chromium\0--user-data-dir=' + profile.encode() + b'\0')
                (directory / 'stat').write_text(f'{pid} (chromium renderer) S 1 {group} 1 0')
            uid = (root / '201').stat().st_uid
            with patch('automation.os.getpgrp', return_value=999, create=True):
                self.assertEqual(owned_browser_groups(RUN, root, uid), {301})
                self.assertEqual(owned_browser_groups(RUN, root, uid + 1), set())


if __name__ == '__main__':
    unittest.main()
