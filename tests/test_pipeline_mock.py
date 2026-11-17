import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from spec_agent.controller import run
from spec_agent.config import Config
from helpers import ROOT,fake_tools

class PipelineTests(unittest.TestCase):
    def pipeline(self,scenario='holds',branch='hoare'):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);t=Path(tmp.name)
        path=fake_tools(t/'bin',scenario)
        with patch.dict(os.environ,{'PATH':path}):
            root,result=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',
                Config(tool_timeout=.3 if scenario=='timeout' else 5,tool_mode='MOCK'),output=t/'runs',
                fixture=ROOT/'examples/clamp'/('infeasible_fixture.json' if scenario=='vacuous' else 'llm_fixture.json'),branch=branch)
        self.assertEqual(json.loads((root/'checkpoint.json').read_text())['state'],'FINISHED')
        return root,result
    def test_clamp_full_mock_pipeline(self):
        root,r=self.pipeline();c=r['contracts'][0]
        self.assertEqual(c['precondition']['status'],'FEASIBLE')
        self.assertEqual([q['verdict'] for q in c['properties']],['HOLDS','HOLDS'])
        self.assertEqual(c['verification']['verdict'],'HOLDS');self.assertEqual(c['evaluation']['status'],'NOT_RUN')
        self.assertTrue(all(q['conclusion_gate']['allowed'] for q in c['properties']))
        self.assertEqual(len(list((root/'verification').glob('*/model.btor2'))),3)
    def test_clause_violation(self):
        _,r=self.pipeline('violated');c=r['contracts'][0]
        self.assertEqual([q['verdict'] for q in c['properties']],['HOLDS','VIOLATED'])
        self.assertEqual(c['verification']['verdict'],'VIOLATED')
    def test_vacuous(self):
        _,r=self.pipeline('vacuous');self.assertEqual(r['contracts'][0]['verification']['verdict'],'VACUOUS')
    def test_conclusion_fail_closed(self):
        for scenario in ['invalid','crash','wrong_map','multi_bad','mutate','conflict','build_fail']:
            with self.subTest(scenario=scenario):
                _,r=self.pipeline(scenario);self.assertEqual(r['contracts'][0]['verification']['verdict'],'ERROR')
    def test_unknown_and_timeout(self):
        for scenario in ['unknown','timeout']:
            _,r=self.pipeline(scenario);self.assertEqual(r['contracts'][0]['verification']['verdict'],'UNKNOWN')
    def test_parallel_distinct_branches(self):
        root,r=self.pipeline(branch='both')
        self.assertTrue(r['generation']['parallel']);self.assertEqual(len(r['static_properties']),1)
        self.assertEqual(r['static_properties'][0]['verdict'],'VIOLATED')
        self.assertTrue((root/'generation/llm').is_dir());self.assertTrue((root/'generation/cbmc').is_dir())
    def test_static_array(self):
        with tempfile.TemporaryDirectory() as t:
            path=fake_tools(Path(t)/'bin')
            with patch.dict(os.environ,{'PATH':path}):
                _,r=run([ROOT/'examples/array_bug/program.c'],ROOT/'examples/array_bug/requirements.md',Config(tool_mode='MOCK'),output=Path(t)/'runs',branch='static')
            self.assertEqual(r['static_properties'][0]['verdict'],'VIOLATED');self.assertEqual(r['contracts'],[])
    def test_missing_tools_still_generates(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':''}):
            _,r=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',Config(),output=t,fixture=ROOT/'examples/clamp/llm_fixture.json')
            self.assertEqual(r['generation']['llm_specs'],1)
            self.assertEqual(r['contracts'][0]['verification']['verdict'],'ERROR')
    def test_generate_only_does_not_verify(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':''}):
            root,r=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',Config(),output=t,fixture=ROOT/'examples/clamp/llm_fixture.json',branch='hoare',generate_only=True)
            self.assertFalse((root/'verification').exists());self.assertEqual(r['contracts'][0]['verification']['verdict'],'NOT_RUN')
