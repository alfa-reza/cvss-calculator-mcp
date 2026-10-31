import concurrent.futures
import http.client
import json
import os
import queue
import sys
import threading
import signal
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V3 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
V4 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N'
CASES = [
    ('2.0', 'AV:N/AC:L/Au:N/C:C/I:C/A:C', 10.0, 'High'),
    ('3.0', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'Critical'),
    ('3.1', V3, 9.8, 'Critical'),
    ('3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0, 'None'),
    ('4.0', V4, 8.7, 'High'),
]


def request(method, params=None, ident=1):
    msg = {'jsonrpc': '2.0', 'id': ident, 'method': method}
    if params is not None:
        msg['params'] = params
    return msg


def check_tools(test, response):
    tools = response['result']['tools']
    test.assertEqual([tool['name'] for tool in tools], ['calculate_cvss'])
    schema = tools[0]['inputSchema']
    test.assertEqual(set(schema['required']), {'version', 'vector'})
    test.assertFalse(schema['additionalProperties'])


def check_score(test, response, expected, version, vector, severity):
    result = response['result']
    test.assertFalse(result.get('isError', False))
    expected_result = {'version': version, 'vector': vector, 'score': expected, 'severity': severity}
    test.assertEqual(json.loads(result['content'][0]['text']), expected_result)


class ResponseReader:
    """Read complete stdio messages without blocking the test indefinitely."""

    def __init__(self, stream):
        self.messages = queue.Queue()
        self.thread = threading.Thread(target=self._read, args=(stream,), daemon=True)
        self.thread.start()

    def _read(self, stream):
        try:
            for line in stream:
                self.messages.put(line)
        finally:
            self.messages.put(None)

    def response(self, timeout=5):
        try:
            line = self.messages.get(timeout=timeout)
        except queue.Empty as error:
            raise TimeoutError('Timed out waiting for MCP stdio response') from error
        if line is None:
            raise EOFError('MCP server closed stdout before responding')
        return json.loads(line)


def check_no_race(test, stderr):
    stderr.seek(0)
    diagnostics = stderr.read().decode(errors='replace')
    test.assertNotIn('WARNING: DATA RACE', diagnostics, diagnostics)


class HarnessTests(unittest.TestCase):
    def test_stdio_timeout_and_cleanup(self):
        proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], stdout=subprocess.PIPE, text=True)
        reader = ResponseReader(proc.stdout)
        try:
            with self.assertRaises(TimeoutError):
                reader.response(timeout=0.1)
        finally:
            proc.kill()
            proc.wait(timeout=5)
            reader.thread.join(timeout=5)
            proc.stdout.close()
        self.assertFalse(reader.thread.is_alive())

    def test_race_report_is_rejected(self):
        with tempfile.TemporaryFile() as stderr:
            stderr.write(b'WARNING: DATA RACE\n')
            stderr.flush()
            with self.assertRaises(AssertionError):
                check_no_race(self, stderr)


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.binary = str(Path(cls.temp.name) / 'cvss-calculator-mcp')
        build = ['go', 'build']
        if os.environ.get('CVSS_TEST_RACE') == '1':
            build.append('-race')
        subprocess.run([*build, '-o', cls.binary, './cmd/cvss-calculator-mcp'], cwd=ROOT, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_cli(self):
        for args, success in [(['--help'], True), (['--version'], True), (['--transport', 'invalid'], False), (['--listen', '127.0.0.1:0'], False), (['--unknown'], False)]:
            with self.subTest(args=args):
                proc = subprocess.run([self.binary, *args], capture_output=True, timeout=5)
                self.assertEqual(proc.returncode == 0, success)

    def test_stdio(self):
        for args in ([], ['--transport', 'stdio']):
            with self.subTest(args=args):
                stderr = tempfile.TemporaryFile()
                self.addCleanup(stderr.close)
                proc = subprocess.Popen([self.binary, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True)
                reader = ResponseReader(proc.stdout)
                try:
                    def call(message):
                        proc.stdin.write(json.dumps(message) + '\n')
                        proc.stdin.flush()
                        return reader.response()
                    call(request('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'test', 'version': '1'}}))
                    proc.stdin.write(json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n')
                    proc.stdin.flush()
                    check_tools(self, call(request('tools/list')))
                    for version, vector, expected, severity in CASES:
                        check_score(self, call(request('tools/call', {'name': 'calculate_cvss', 'arguments': {'version': version, 'vector': vector}})), expected, version, vector, severity)
                finally:
                    proc.stdin.close()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                        self.fail('stdio server did not stop after EOF')
                    finally:
                        reader.thread.join(timeout=5)
                        proc.stdout.close()
                        check_no_race(self, stderr)
                self.assertEqual(proc.returncode, 0)

    def test_http(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            reserved.listen()
            port = reserved.getsockname()[1]
            occupied = subprocess.run([self.binary, '--transport', 'http', '--listen', f'127.0.0.1:{port}'], capture_output=True, timeout=5)
            self.assertNotEqual(occupied.returncode, 0)
        stderr = tempfile.TemporaryFile()
        self.addCleanup(stderr.close)
        proc = subprocess.Popen([self.binary, '--transport', 'http', '--listen', f'127.0.0.1:{port}'], stderr=stderr)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                self.fail('HTTP server did not start')
            def post(message, headers=None):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                base = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-06-18'}
                base.update(headers or {})
                conn.request('POST', '/mcp', json.dumps(message), base)
                response = conn.getresponse()
                status, body = response.status, response.read()
                conn.close()
                return status, body
            status, body = post(request('tools/list'))
            self.assertEqual(status, 200)
            check_tools(self, json.loads(body))
            for version, vector, expected, severity in CASES:
                status, body = post(request('tools/call', {'name': 'calculate_cvss', 'arguments': {'version': version, 'vector': vector}}))
                self.assertEqual(status, 200)
                check_score(self, json.loads(body), expected, version, vector, severity)
            for args in [{'version': '3.1', 'vector': 'bad'}, {'version': '3.1', 'vector': 'bad', 'extra': True}, {'version': None, 'vector': 'bad'}, {'vector': 'bad'}, {'version': 3.1, 'vector': 'bad'}]:
                status, body = post(request('tools/call', {'name': 'calculate_cvss', 'arguments': args}))
                self.assertTrue(status >= 400 or 'error' in json.loads(body) or json.loads(body).get('result', {}).get('isError'))
            for headers in ({'Origin': 'https://evil.example'}, {'Host': 'evil.example'}):
                self.assertEqual(post(request('tools/list'), headers)[0], 403)
            def parallel_call(_):
                return post(request('tools/call', {'name': 'calculate_cvss', 'arguments': {'version': '3.1', 'vector': V3}}))
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                for status, body in pool.map(parallel_call, range(12)):
                    self.assertEqual(status, 200)
                    check_score(self, json.loads(body), 9.8, '3.1', V3, 'Critical')
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                self.fail('HTTP server did not stop')
            finally:
                check_no_race(self, stderr)
        self.assertEqual(proc.returncode, 0)


if __name__ == '__main__':
    unittest.main()
