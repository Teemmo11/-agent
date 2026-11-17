"""Opt-in real tools; fixture LLM only. Never execute the C program natively."""
import os
import tempfile
import unittest
from pathlib import Path
from spec_agent.config import load_config
from spec_agent.controller import run
from helpers import ROOT

@unittest.skipUnless(os.environ.get('SPEC_AGENT_REAL_TESTS')=='1','Set SPEC_AGENT_REAL_TESTS=1 with compatible tools on PATH')
class RealToolchainTests(unittest.TestCase):
    def test_clamp_real_tools(self):
        with tempfile.TemporaryDirectory() as t:
            _,r=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',load_config(ROOT/'.env'),
                output=t,fixture=ROOT/'examples/clamp/llm_fixture.json',branch='hoare')
            self.assertEqual(r['contracts'][0]['precondition']['status'],'FEASIBLE')
            self.assertEqual(r['contracts'][0]['verification']['verdict'],'HOLDS')
    def test_bug_real_tools(self):
        with tempfile.TemporaryDirectory() as t:
            _,r=run([ROOT/'examples/clamp/buggy.c'],ROOT/'examples/clamp/requirements.md',load_config(ROOT/'.env'),
                output=t,fixture=ROOT/'examples/clamp/llm_fixture.json',branch='hoare')
            self.assertEqual(r['contracts'][0]['verification']['verdict'],'VIOLATED')
            self.assertEqual(r['contracts'][0]['properties'][1]['verdict'],'VIOLATED')
    def test_array_real_tools(self):
        with tempfile.TemporaryDirectory() as t:
            _,r=run([ROOT/'examples/array_bug/program.c'],ROOT/'examples/array_bug/requirements.md',load_config(ROOT/'.env'),output=t,branch='static')
            self.assertTrue(any(p.get('verdict')=='VIOLATED' for p in r['static_properties']))
