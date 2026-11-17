import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from spec_agent.trace import RunTrace, read_events, redact
from spec_agent.controller import run
from spec_agent.config import Config
from spec_agent.cli import main
from spec_agent.errors import AgentError
from helpers import ROOT, fake_tools


class TraceReviewTests(unittest.TestCase):
    def pipeline(self, base, scenario='holds', branch='both', **kwargs):
        path=fake_tools(base/'bin',scenario)
        with patch.dict(os.environ,{'PATH':path}):
            return run([ROOT/'examples/clamp/program.c'], ROOT/'examples/clamp/requirements.md',
                       Config(tool_mode='MOCK',tool_timeout=.15 if scenario=='timeout' else 5),
                       output=base/'runs',fixture=ROOT/'examples/clamp/llm_fixture.json',branch=branch,**kwargs)

    def test_static_and_hoare_tools_have_paired_correlated_events(self):
        with tempfile.TemporaryDirectory() as t:
            root,result=self.pipeline(Path(t))
            events=list(read_events(root/'events.jsonl'))
            started={r['details']['command_id']:r for r in events if r['event']=='tool.started'}
            ended={r['details']['command_id']:r for r in events if r['event']=='tool.finished'}
            self.assertEqual(started.keys(),ended.keys())
            self.assertEqual(result['logging']['status'],'COMPLETE')
            self.assertEqual(events[0]['event'],'run.started')
            self.assertIn('static.candidate',[e['event'] for e in events])
            finished=[r for r in events if r['event']=='verification.finished']
            self.assertEqual(len(finished),4)
            for record in finished:
                ctx=record['context']
                self.assertIn('spec_id',ctx); self.assertIn('property_id',ctx)
                if ctx['branch']=='hoare': self.assertIn('function_id',ctx)
                saved=json.loads((root/record['details']['result_file']).read_text())
                self.assertEqual(record['details']['verdict'],saved['verdict'])
            self.assertNotIn(str(root),(root/'events.jsonl').read_text())

    def test_sink_failure_does_not_change_verification_and_is_reported(self):
        original=Path.open
        def faulty(path,*args,**kwargs):
            if path.name=='events.jsonl': raise OSError('simulated log disk failure')
            return original(path,*args,**kwargs)
        with tempfile.TemporaryDirectory() as t,patch.object(Path,'open',faulty),contextlib.redirect_stderr(io.StringIO()) as stderr:
            root,result=self.pipeline(Path(t),branch='hoare')
            self.assertEqual(result['contracts'][0]['verification']['verdict'],'HOLDS')
            self.assertEqual(result['logging']['status'],'DEGRADED')
            self.assertGreater(result['logging']['dropped_events'],0)
            self.assertEqual(stderr.getvalue().count('WARNING'),1)
            self.assertIn('run.finished',(root/'process.log').read_text())
            self.assertEqual(json.loads((root/'result.json').read_text())['logging'],result['logging'])

    def test_capacity_limit_keeps_logs_bounded_and_records_loss(self):
        with tempfile.TemporaryDirectory() as t,contextlib.redirect_stderr(io.StringIO()):
            root,result=self.pipeline(Path(t),branch='hoare',log_max_bytes=1024)
            self.assertEqual(result['contracts'][0]['verification']['verdict'],'HOLDS')
            self.assertEqual(result['logging']['status'],'DEGRADED')
            for file in ('events.jsonl','process.log'): self.assertLessEqual((root/file).stat().st_size,1024)
            list(read_events(root/'events.jsonl')) # No partially appended event on limit.

    def test_timeout_has_tool_evidence_and_unknown_verdict(self):
        with tempfile.TemporaryDirectory() as t:
            root,result=self.pipeline(Path(t),scenario='timeout',branch='hoare')
            records=list(read_events(root/'events.jsonl'))
            self.assertTrue(any(r['event']=='tool.finished' and r['details']['timed_out'] for r in records))
            self.assertEqual(result['contracts'][0]['verification']['verdict'],'UNKNOWN')
            self.assertTrue(any(r['event']=='verification.finished' and r['level']=='WARNING' for r in records))

    def test_cli_filter_works_without_loading_config_and_on_moved_run(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t);trace=RunTrace(base,'run')
            trace.bind(function_id='f',spec_id='s').emit('spec.accepted',x=1)
            trace.bind(function_id='g').emit('spec.accepted',x=2)
            with patch('spec_agent.cli.load_config',side_effect=AssertionError('must not load configuration')),contextlib.redirect_stdout(io.StringIO()) as out:
                status=main(['logs','--run',str(base),'--function-id','f','--json'])
            self.assertEqual(status,0)
            rows=[json.loads(line) for line in out.getvalue().splitlines()]
            self.assertEqual(len(rows),1); self.assertEqual(rows[0]['context']['spec_id'],'s')
            with (base/'events.jsonl').open('a') as stream: stream.write('{"unfinished":')
            with self.assertRaises(AgentError): list(read_events(base/'events.jsonl'))

    def test_escaped_keys_fields_and_overlapping_secrets_are_redacted(self):
        secret='my"\\密钥'
        value={'payload':json.dumps({'token':secret}),'Authorization':'Bearer anything',
               'nested':[secret], 'text':'long-secret-value'}
        safe=redact(value,('long-secret', 'long-secret-value',secret))
        self.assertEqual(safe['Authorization'],'[REDACTED]')
        self.assertEqual(safe['text'],'[REDACTED]')
        self.assertNotIn(secret,json.loads(safe['payload'])['token'])
        self.assertEqual(safe['nested'],['[REDACTED]'])

    def test_serialization_error_and_existing_file_are_not_silent(self):
        with tempfile.TemporaryDirectory() as t,contextlib.redirect_stderr(io.StringIO()):
            root=Path(t);trace=RunTrace(root,'run')
            trace.emit('bad',value=object())
            self.assertEqual(trace.status()['status'],'DEGRADED')
            trace.emit('good',value=1)
            original=(root/'events.jsonl').read_bytes()
            second=RunTrace(root,'other')
            second.emit('should.not.append')
            self.assertEqual((root/'events.jsonl').read_bytes(),original)
            self.assertEqual(second.status()['status'],'DEGRADED')

    def test_old_guard_mapping_and_probe_snapshots(self):
        with tempfile.TemporaryDirectory() as t:
            from spec_agent.analysis.functions import CAnalyzer
            from spec_agent.spec.formalizer import formalize
            from spec_agent.spec.harness import emit_harness
            base=Path(t);source=base/'p.c';source.write_text('int f(int x) { return x; }')
            func=CAnalyzer().analyze([source]).functions[0]
            spec={'spec_id':'HS-test','function_spec':{'pre_condition':{'formal_candidate':'x >= 0'},
                  'post_conditions':[{'clause_id':'Q1','formal_candidate':'result == old(x)','guard':'old(x) >= 0'}]}}
            trace=RunTrace(base,'test').bind(function_id=func.function_id,spec_id=spec['spec_id'])
            contract=formalize(spec,func,{'source_sha256':'s','requirements_sha256':'r'},trace=trace)
            emit_harness(func,contract,None,[source],base/'p',trace=trace)
            emit_harness(func,contract,contract.ensures[0],[source],base/'q',trace=trace)
            records=list(read_events(base/'events.jsonl'))
            expressions=[r for r in records if r['event']=='expression.validated']
            self.assertEqual(len(expressions),3)
            self.assertIn('__sa_old_x',expressions[1]['details']['converted'])
            harnesses=[r['details'] for r in records if r['event']=='harness.emitted']
            self.assertEqual(harnesses[0]['snapshots'],[])
            self.assertEqual(harnesses[1]['snapshots'],['x'])
            self.assertIn('__sa_guard',harnesses[1]['assertion'])

    def test_custom_client_tracing_keeps_caller_propagation(self):
        from test_caller_propagation import DynamicClient
        from spec_agent.analysis.functions import CAnalyzer
        from spec_agent.generators.llm_hoare import generate
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);source=root/'p.c';source.write_text('int f(int x) { return x; }\nint main(void) { return f(2); }')
            program=CAnalyzer().analyze([source]);trace=RunTrace(root,'run')
            result=generate(program,{'ids':['REQ-1'],'raw_text':'REQ-1 nonnegative'},
                            {'source_sha256':'s','requirements_sha256':'r'},DynamicClient(),root/'generation',trace=trace)
            self.assertFalse(result['failures'])
            events=list(read_events(root/'events.jsonl'))
            propagated=next(e for e in events if e['event']=='expectation.propagated')
            self.assertIn('caller_function_id',propagated['details'])
            self.assertIn('callee_function_id',propagated['details'])

    def test_cancelled_run_has_terminal_record(self):
        with tempfile.TemporaryDirectory() as t,patch('spec_agent.controller.CAnalyzer.analyze',side_effect=KeyboardInterrupt):
            root,result=self.pipeline(Path(t),branch='hoare')
            self.assertEqual(result['status'],'CANCELLED')
            from spec_agent.llm.schema import validate
            validate(result,json.loads((ROOT/'schemas/result.schema.json').read_text()))
            self.assertEqual(list(read_events(root/'events.jsonl'))[-1]['event'],'run.cancelled')

    def test_preflight_block_records_capabilities_before_failure(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':''}):
            root,result=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',
                            Config(),output=t,require_real=True)
            records=list(read_events(root/'events.jsonl'))
            self.assertEqual(result['status'],'FAILED')
            self.assertIn('preflight.finished',[r['event'] for r in records])
            self.assertEqual(records[-1]['details']['failed_stage'],'PREFLIGHT')

    def test_request_error_reports_stage_and_does_not_publish_spec(self):
        with tempfile.TemporaryDirectory() as t,patch('spec_agent.llm.client.FixtureClient.complete',side_effect=AgentError('LLM_HTTP_ERROR','HTTP 429')):
            root,result=self.pipeline(Path(t),branch='hoare',generate_only=True)
            records=list(read_events(root/'events.jsonl'))
            failure=next(r for r in records if r['event']=='llm.generation.failed')
            self.assertEqual(failure['details']['stage'],'request')
            self.assertEqual(failure['details']['error']['code'],'LLM_HTTP_ERROR')
            self.assertEqual(result['generation']['llm_specs'],0)

    def test_invalid_optional_metadata_does_not_reject_valid_spec(self):
        from test_caller_propagation import DynamicClient
        from spec_agent.analysis.functions import CAnalyzer
        from spec_agent.generators.llm_hoare import generate
        class Client(DynamicClient):
            def complete(self,messages,directory):
                (directory/'response.metadata.json').write_text('{broken')
                return super().complete(messages,directory)
        with tempfile.TemporaryDirectory() as t:
            base=Path(t);source=base/'p.c';source.write_text('int f(int x) { return x; }')
            result=generate(CAnalyzer().analyze([source]),{'ids':['REQ-1'],'raw_text':'REQ-1'},
                            {'source_sha256':'s','requirements_sha256':'r'},Client(),base/'generation',trace=RunTrace(base,'test'))
            self.assertFalse(result['failures'])
            self.assertIn('llm.metadata.unavailable',[r['event'] for r in read_events(base/'events.jsonl')])
