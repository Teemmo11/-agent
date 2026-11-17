import os
import sys
import tempfile
import unittest
from pathlib import Path
from spec_agent.process import invoke
class ProcessTests(unittest.TestCase):
    def test_timeout_and_log_limit(self):
        with tempfile.TemporaryDirectory() as t:
            r=invoke([sys.executable,'-c','import time;time.sleep(5)'],cwd=Path(t),timeout=.1)
            self.assertTrue(r.timed_out)
            r=invoke([sys.executable,'-c','print("x"*10000)'],cwd=Path(t),prefix='flood',max_log_bytes=128)
            self.assertEqual(r.resource_limit,'LOG_LIMIT_EXCEEDED')
            self.assertLessEqual(Path(r.stdout_path).stat().st_size,128)
    def test_exclusive_logs(self):
        with tempfile.TemporaryDirectory() as t:
            invoke([sys.executable,'-c','print(1)'],cwd=Path(t))
            with self.assertRaises(FileExistsError):invoke([sys.executable,'-c','print(2)'],cwd=Path(t))
    def test_secret_env_not_inherited(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'LLM_API_KEY':'SENSITIVE'}):
            r=invoke([sys.executable,'-c','import os;print(os.getenv("LLM_API_KEY"))'],cwd=Path(t))
            self.assertEqual(Path(r.stdout_path).read_text().strip(),'None')
