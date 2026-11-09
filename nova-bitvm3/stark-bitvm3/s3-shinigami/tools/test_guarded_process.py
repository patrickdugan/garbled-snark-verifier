"""Fast, offline regression checks for the opt-in RSS watchdog."""
import sys
import tempfile
import unittest
from pathlib import Path
from guarded_process import guarded_run, write_report


class GuardTests(unittest.TestCase):
    def run_case(self, code, *, seconds=2, rss=256 * 1024 * 1024):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            result = guarded_run([sys.executable, '-c', code], cwd=directory,
                                 log_path=directory/'log.txt',
                                 timeout_seconds=seconds, max_rss_bytes=rss)
            write_report(directory/'result.json', result)
            self.assertTrue((directory/'result.json').exists())
            return result

    def test_success(self):
        got = self.run_case("print('ok')")
        self.assertEqual(got['status'], 'success')
        self.assertEqual(got['returncode'], 0)
        self.assertGreater(got['samples'], 0)
        self.assertFalse(got['address_space_rlimit_applied'])

    def test_nonzero_exit(self):
        got = self.run_case('import sys;sys.exit(23)')
        self.assertEqual(got['status'], 'command_failed')
        self.assertEqual(got['returncode'], 23)

    def test_time_limit(self):
        got = self.run_case('import time;time.sleep(2)', seconds=0.20)
        self.assertEqual(got['status'], 'timeout')

    def test_rss_limit(self):
        got = self.run_case(
            'import time;x=bytearray(90*1024*1024);time.sleep(1)',
            rss=130*1024*1024)
        self.assertEqual(got['status'], 'rss_budget_exceeded')
        self.assertGreater(got['peak_rss_bytes'], 130*1024*1024)

    def test_subprocess_is_counted(self):
        code = ("import subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c',"
                "'import time;x=bytearray(90*1024*1024);time.sleep(2)']);"
                "time.sleep(2)")
        got = self.run_case(code, rss=140*1024*1024)
        self.assertEqual(got['status'], 'rss_budget_exceeded')
        self.assertGreaterEqual(got['peak_processes'], 2)

    def test_invalid_budget(self):
        with self.assertRaises(ValueError):
            guarded_run([], cwd=Path('.'), log_path=Path('/tmp/unused'),
                        timeout_seconds=1, max_rss_bytes=10)


if __name__=='__main__':
    unittest.main()
