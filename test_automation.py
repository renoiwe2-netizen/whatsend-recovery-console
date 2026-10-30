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
from automation import owned_browser_groups, managed_processes_closed, memory_counters, cleanup_task_files, Automation

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
        self.closed_patch = patch('automation.managed_processes_closed', return_value=True)
        self.cleanup_patch = patch('automation.cleanup_task_files')
        self.memory_patch = patch('automation.memory_counters', return_value={})
        self.groups_patch.start()
        self.closed_patch.start()
        self.cleanup_mock = self.cleanup_patch.start()
        self.memory_patch.start()
        self.signal_patch.start()
        self.kill_patch.start()
        self.auth = {'Authorization': 'Bearer ' + KEY}

    async def asyncTearDown(self):
        await self.client.close()
        self.kill_patch.stop()
        self.signal_patch.stop()
        self.groups_patch.stop()
        self.closed_patch.stop()
        self.cleanup_patch.stop()
        self.memory_patch.stop()

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

    async def test_report_canceled_is_a_supported_terminal_result(self):
        await self.begin(mode='report')
        await self.finish({'status': 'report_canceled'})
        self.assertEqual(self.automation.records[RUN]['status'], 'report_canceled')

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

    async def test_status_proves_supervised_closure_only_after_exit_and_scan(self):
        await self.begin()
        response = await self.client.post('/automation/status', headers=self.auth, json={'run_id': RUN})
        self.assertFalse((await response.json())['process_closed'])
        await self.finish({'status': 'idle'})
        response = await self.client.post('/automation/status', headers=self.auth, json={'run_id': RUN})
        result = await response.json()
        self.assertEqual(result['status'], 'idle')
        self.assertTrue(result['process_closed'])
        self.assertEqual(result['closure_source'], 'supervisor')
        self.assertEqual(result['exit_code'], 0)
        self.assertRegex(result['boot_id'], r'^[a-f0-9-]{36}$')
        self.cleanup_mock.assert_called_once_with(RUN)
        with patch('automation.managed_processes_closed', return_value=False):
            response = await self.client.post('/automation/status', headers=self.auth, json={'run_id': RUN})
            self.assertFalse((await response.json())['process_closed'])

    async def test_unknown_run_after_restart_requires_a_fresh_idle_process_scan(self):
        response = await self.client.post('/automation/status', headers=self.auth, json={'run_id': RUN})
        result = await response.json()
        self.assertEqual(result['status'], 'unknown')
        self.assertTrue(result['process_closed'])
        self.assertEqual(result['closure_source'], 'fresh_proc_scan')
        self.assertEqual(self.processes, [])
        self.assertEqual(self.kills, [])
        self.assertNotEqual(self.automation.boot_id, Automation(self.gateway).boot_id)
        for state in ('process-present', 'scan-error', 'human-busy', 'automation-busy'):
            with self.subTest(state=state):
                self.gateway.session = {'status': 'ready'} if state == 'human-busy' else None
                self.automation.active_run = OTHER if state == 'automation-busy' else None
                with patch('automation.managed_processes_closed', return_value=state not in ('process-present', 'scan-error')):
                    response = await self.client.post('/automation/status', headers=self.auth, json={'run_id': RUN})
                    self.assertFalse((await response.json())['process_closed'])
        self.gateway.session = None
        self.automation.active_run = None

    async def test_status_refuses_browser_origin_and_unauthenticated_reads(self):
        for headers, expected in [({}, 401), ({**self.auth, 'Origin': ORIGIN}, 403)]:
            response = await self.client.post('/automation/status', headers=headers, json={'run_id': RUN})
            self.assertEqual(response.status, expected)
        self.assertEqual(self.processes, [])
        self.assertEqual(self.kills, [])

    async def test_a_known_run_cannot_claim_closure_without_supervisor_exit_proof(self):
        self.automation.records[RUN] = {'run_id': RUN, 'status': 'failed', 'process_closed': False}
        response = await self.client.post('/automation/status', headers=self.auth, json={'run_id': RUN})
        self.assertFalse((await response.json())['process_closed'])

    async def test_cgroup_oom_is_numeric_metadata_and_never_a_retry(self):
        with patch('automation.memory_counters', side_effect=[{'oom_kill': 3}, {'oom_kill': 4, 'limit_bytes': 536870912, 'peak_bytes': 536870912}]):
            await self.begin()
            await self.finish({'status': 'failed', 'code': 'HOSTED_RUNNER_FAILED'}, code=-9)
        response = await self.client.post('/automation/status', headers=self.auth, json={'run_id': RUN})
        result = await response.json()
        self.assertEqual(result['code'], 'HOSTED_MEMORY_LIMIT_REACHED')
        self.assertEqual(result['memory']['oom_kill_delta'], 1)
        self.assertEqual(result['memory']['limit_bytes'], 512 * 1024 * 1024)
        self.assertTrue(result['process_closed'])
        self.assertEqual((await self.begin()).status, 200)
        self.assertEqual(len(self.processes), 1)


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

    def test_fresh_scan_refuses_any_owned_loader_or_any_private_task_browser(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / '201'
            directory.mkdir()
            uid = directory.stat().st_uid
            arguments = [b'node\0/opt/poc/runner-loader.mjs\0',
                         b'chromium\0--user-data-dir=/tmp/private-task-' + OTHER.encode() + b'-abcdef/profile\0']
            for value in arguments:
                (directory / 'cmdline').write_bytes(value)
                self.assertFalse(managed_processes_closed(root, uid))
                self.assertTrue(managed_processes_closed(root, uid + 1))
            (directory / 'cmdline').write_bytes(b'python3\0/opt/poc/server.py\0')
            self.assertTrue(managed_processes_closed(root, uid))
            (directory / 'cmdline').unlink()
            self.assertFalse(managed_processes_closed(root, uid))
            self.assertFalse(managed_processes_closed(root / 'missing', uid))
            with patch.object(Path, 'read_bytes', side_effect=PermissionError('private detail')):
                self.assertFalse(managed_processes_closed(root, uid))

    def test_cleanup_is_exact_run_and_owner_scoped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / ('private-task-' + RUN + '-abcdef')
            foreign = root / ('private-task-' + OTHER + '-abcdef')
            for directory in (current, foreign):
                directory.mkdir()
                (directory / 'media').mkdir()
                (directory / 'media' / 'synthetic.bin').write_bytes(b'private temporary fixture')
            uid = current.stat().st_uid
            with self.assertRaises(ValueError):
                cleanup_task_files(RUN, root, uid + 1)
            self.assertTrue(current.exists())
            cleanup_task_files(RUN, root, uid)
            self.assertFalse(current.exists())
            self.assertTrue(foreign.exists())
            with self.assertRaises(ValueError):
                cleanup_task_files('../escape', root, uid)

    def test_memory_projection_ignores_raw_values_and_unknown_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, value in {'memory.current': '500', 'memory.peak': '800', 'memory.max': '536870912',
                                'memory.events': 'oom 1\noom_kill 1\nmax 2\nPRIVATE_SECRET 3\n'}.items():
                (root / name).write_text(value)
            self.assertEqual(memory_counters(root), {'current_bytes': 500, 'peak_bytes': 800, 'limit_bytes': 536870912,
                                                     'oom': 1, 'oom_kill': 1, 'max': 2})


if __name__ == '__main__':
    unittest.main()
