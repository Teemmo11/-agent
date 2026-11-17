"""Opt-in live LLM + real-tool acceptance; no fixture route."""
import os
import tempfile
import unittest
from scripts.real_validation import main

@unittest.skipUnless(os.environ.get('SPEC_AGENT_LIVE_TESTS')=='1','Requires real LLM credentials and compatible tools; no fallback')
class LiveAcceptanceTests(unittest.TestCase):
    def test_sequential_acceptance(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(main(['--case','all','--output',t]),0)
