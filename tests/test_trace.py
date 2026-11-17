import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from spec_agent.trace import RunTrace
from spec_agent.controller import run
from spec_agent.config import Config
from helpers import ROOT, fake_tools


class TraceTests(unittest.TestCase):
    def test_parallel_serialization_and_redaction(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); secret='secret"\\key'
            trace=RunTrace(root,'run',secrets=(secret,))
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda i: trace.emit('test',value=secret,index=i),range(30)))
            records=[json.loads(s) for s in (root/'events.jsonl').read_text().splitlines()]
            self.assertEqual([r['sequence'] for r in records],list(range(1,31)))
            self.assertTrue(all(r['details']['value']=='[REDACTED]' for r in records))
            self.assertNotIn(secret,(root/'process.log').read_text())

    def execute(self,root,fixture,generate_only=False):
        path=fake_tools(root/'bin')
        with patch.dict(os.environ,{'PATH':path}):
            return run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',
                       Config(tool_mode='MOCK'),output=root/'runs',fixture=fixture,
                       branch='hoare',generate_only=generate_only)

    def test_trace_correlates_source_spec_and_actual_assertions(self):
        with tempfile.TemporaryDirectory() as t:
            root,result=self.execute(Path(t),ROOT/'examples/clamp/llm_fixture.json')
            self.assertEqual(result['status'],'COMPLETED')
            events=[json.loads(s) for s in (root/'events.jsonl').read_text().splitlines()]
            by_event={e['event']:e['details'] for e in events}
            self.assertEqual(by_event['analysis.partitioned']['strategy'],'DETERMINISTIC_C_AST_FUNCTIONS')
            self.assertEqual(by_event['spec.accepted']['function_spec']['pre_condition']['formal_candidate'],'low <= high')
            harnesses=[e['details'] for e in events if e['event']=='harness.emitted']
            self.assertEqual(len(harnesses),3)
            for h in harnesses:
                actual=(root/h['harness_file']).read_text().splitlines()[h['assertion_line']-1].strip()
                self.assertEqual(h['assertion'],actual)
                self.assertEqual(h['spec_id'],result['contracts'][0]['spec_id'])
                if h['kind']=='PRECONDITION_FEASIBILITY': self.assertEqual(h['snapshots'],[])
            self.assertEqual(events[-1]['event'],'run.finished')

    def test_invalid_model_output_and_generate_only_are_explicit(self):
        for invalid in (True,False):
            with self.subTest(invalid=invalid),tempfile.TemporaryDirectory() as t:
                base=Path(t); fixture=base/'fixture.json'
                data=json.loads((ROOT/'examples/clamp/llm_fixture.json').read_text())
                if invalid: data['clamp']['function_spec']['function']['name']='wrong'
                fixture.write_text(json.dumps(data))
                root,result=self.execute(base,fixture,generate_only=True)
                events=[json.loads(s) for s in (root/'events.jsonl').read_text().splitlines()]
                names=[e['event'] for e in events]
                self.assertNotIn('harness.emitted',names)
                if invalid:
                    failed=next(e['details'] for e in events if e['event']=='llm.generation.failed')
                    self.assertEqual(failed['stage'],'parse_and_validate')
                    self.assertEqual(failed['error']['code'],'LLM_RESPONSE_INVALID')
                    self.assertNotIn('spec.accepted',names)
                else: self.assertIn('formalization.skipped',names)

    def test_formalization_rejection_is_logged(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t); fixture=base/'fixture.json'
            data=json.loads((ROOT/'examples/clamp/llm_fixture.json').read_text())
            data['clamp']['function_spec']['pre_condition']['formal_candidate']='missing_symbol > 0'
            fixture.write_text(json.dumps(data))
            root,result=self.execute(base,fixture)
            events=[json.loads(s) for s in (root/'events.jsonl').read_text().splitlines()]
            names=[e['event'] for e in events]
            self.assertIn('spec.accepted',names)
            self.assertIn('formalization.rejected',names)
            self.assertNotIn('harness.emitted',names)
            self.assertEqual(result['status'],'COMPLETED_WITH_ERRORS')

    def test_run_failure_is_logged(self):
        with tempfile.TemporaryDirectory() as t:
            root,result=run([],Path(t)/'missing.md',Config(),output=Path(t)/'runs')
            events=[json.loads(s) for s in (root/'events.jsonl').read_text().splitlines()]
            self.assertEqual(result['status'],'FAILED')
            self.assertEqual(events[-1]['event'],'run.failed')
