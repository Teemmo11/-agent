"""C2Btor adapter regressions with explicitly artificial tool evidence."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from helpers import ROOT,fake_tools
from spec_agent.config import Config
from spec_agent.controller import run
from spec_agent.verification.audit import audit_run

class C2BtorContractTests(unittest.TestCase):
    def execute(self,t,scenario):
        with patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin',scenario)}):
            return run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',
                Config(tool_mode='MOCK'),output=Path(t)/'runs',fixture=ROOT/'examples/clamp/llm_fixture.json',branch='hoare')

    def test_queries_and_audit(self):
        for scenario in ('c2btor_holds','c2btor_folded'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as t:
                root,r=self.execute(t,scenario)
                self.assertEqual(r['contracts'][0]['verification']['verdict'],'HOLDS')
                q=r['contracts'][0]['properties'][0]
                self.assertEqual(q['model_contract']['status'],'PASSED')
                self.assertEqual(q['model_contract']['raw_result'],'UNSAT')
                self.assertEqual(q['bad_node'],4)
                self.assertEqual(audit_run(root,require_real=False)['status'],'PASSED')
                self.assertIn('NON_REAL_RUN',audit_run(root)['errors'])
                self.assertIn('5 bad',Path(q['model_contract']['converter_model']).read_text())
                self.assertNotIn('5 bad',(Path(q['evidence_manifest']).parent/'model.btor2').read_text())

    def test_boundaries_block_claims(self):
        for scenario,raw in [('c2btor_boundary_sat','SAT'),('c2btor_boundary_unknown','UNKNOWN')]:
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as t:
                _,r=self.execute(t,scenario);q=r['contracts'][0]['properties'][0]
                self.assertEqual(q['verdict'],'UNKNOWN')
                self.assertFalse(q['conclusion_gate']['allowed'])
                self.assertEqual(q['model_contract']['raw_result'],raw)

    def test_invalid_contracts_fail_closed(self):
        for scenario in ('c2btor_missing_contract','c2btor_map_mismatch','c2btor_no_selection','c2btor_merged'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as t:
                _,r=self.execute(t,scenario);q=r['contracts'][0]['properties'][0]
                self.assertEqual(q['verdict'],'ERROR')
                self.assertEqual(q['error']['code'],'MODEL_CONTRACT_INVALID')
                self.assertFalse(q['conclusion_gate']['allowed'])
                self.assertNotIn('ric3',q['execution_refs'])

    def test_boundary_evidence_tamper(self):
        with tempfile.TemporaryDirectory() as t:
            root,r=self.execute(t,'c2btor_holds');q=r['contracts'][0]['properties'][0]
            Path(q['model_contract']['boundary_model']).write_text('altered\n')
            self.assertEqual(audit_run(root,require_real=False)['status'],'FAILED')

    def test_missing_boundary_metadata_cannot_bypass_audit(self):
        with tempfile.TemporaryDirectory() as t:
            root,r=self.execute(t,'c2btor_holds');q=r['contracts'][0]['properties'][0]
            q.pop('model_contract')
            disk=Path(q['evidence_manifest']).parent/'result.json'
            data=json.loads(disk.read_text());data.pop('model_contract');disk.write_text(json.dumps(data))
            (root/'result.json').write_text(json.dumps(r))
            self.assertEqual(audit_run(root,require_real=False)['status'],'FAILED')
