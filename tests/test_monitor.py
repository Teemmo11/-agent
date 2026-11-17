"""Observation semantics, incremental reads and read-only HTTP boundaries."""
import json
import contextlib
import io
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from spec_agent.artifacts import sha256_file,write_json_atomic
from spec_agent.monitor.state import RunView,RunRegistry
from spec_agent.monitor.server import Monitor,ASSETS
from spec_agent.trace import RunTrace
from spec_agent.cli import main
from helpers import ROOT,fake_tools


class MonitorStateTests(unittest.TestCase):
    def test_opt_in_pq_prefers_formal_spec_and_reads_live_semantic_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = RunTrace(root, 'pq')
            trace.emit('run.started', branch='hoare', tool_mode='REAL')
            trace.emit('analysis.function', function_id='F-1', function='clamp')
            spec_id = 'HS-F-1'
            view = RunView(root, show_pq=True)
            self.assertEqual(view.refresh()['specifications'], [])
            candidate = root/'generation/llm/functions/F-1/spec.json'
            candidate.parent.mkdir(parents=True)
            write_json_atomic(candidate, {'spec_id': spec_id, 'function_spec': {
                'pre_condition': {'formal_candidate': 'low <= high'},
                'post_conditions': [{'clause_id': 'Q1', 'formal_candidate': 'result <= high', 'guard': 'x > high'}],
            }})
            trace.bind(function_id='F-1', spec_id=spec_id).emit('spec.accepted')
            semantic = view.refresh()['specifications'][0]
            self.assertEqual(semantic['source'], 'SEMANTIC')
            self.assertEqual(semantic['precondition'], 'low <= high')
            self.assertEqual(semantic['postconditions'][0]['guard'], 'x > high')
            formal = root/f'specs/formal/{spec_id}.json'
            formal.parent.mkdir(parents=True)
            write_json_atomic(formal, {'source_spec_id': spec_id, 'precondition_expr': '(low <= high)',
                'ensures': [{'clause_id': 'Q1', 'expr': '(__sa_result <= high)', 'guard_expr': '(x > high)'}]})
            write_json_atomic(root/'result.json', {'contracts': [{'spec_id': spec_id, 'function': 'clamp'}]})
            (root/'events.jsonl').unlink()
            historical = RunView(root, show_pq=True).refresh()['specifications'][0]
            self.assertEqual(historical['source'], 'FORMAL')
            self.assertEqual(historical['postconditions'], [
                {'id': 'Q1', 'expression': '(__sa_result <= high)', 'guard': '(x > high)'}])
            self.assertNotIn('specifications', RunView(root).refresh())

    def test_live_partial_line_recovers_and_never_invents_a_verdict(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);trace=RunTrace(root,'live');trace.emit('run.started',branch='hoare',tool_mode='REAL')
            trace.emit('stage.changed',state='VERIFYING');trace.bind(property_id='S.Q1').emit('verification.started',kind='HOARE_POSTCONDITION')
            view=RunView(root);first=view.refresh()
            self.assertEqual(first['stage'],'VERIFYING');self.assertIsNone(first['properties'][0]['verdict'])
            event={'event':'verification.finished','sequence':4,'timestamp':'2026-11-07T10:00:00+00:00',
                   'context':{'property_id':'S.Q1'},'details':{'verdict':'UNKNOWN','raw_result':None,'conclusion_gate':{'allowed':False}}}
            raw=json.dumps(event).encode();cut=len(raw)//2
            with (root/'events.jsonl').open('ab') as f:f.write(raw[:cut])
            partial=view.refresh();self.assertIsNone(partial['properties'][0]['verdict']);self.assertTrue(partial['warnings'])
            with (root/'events.jsonl').open('ab') as f:f.write(raw[cut:]+b'\n')
            final=view.refresh();self.assertEqual(final['properties'][0]['verdict'],'UNKNOWN')
            self.assertFalse(final['properties'][0]['gate']['allowed']);self.assertEqual(view.bad_lines,0)

    def test_feasibility_sat_is_not_a_business_violation(self):
        with tempfile.TemporaryDirectory() as t:
            trace=RunTrace(t,'P');ctx=trace.bind(property_id='S.P-FEASIBILITY',spec_id='S',branch='hoare')
            ctx.emit('verification.started',kind='PRECONDITION_FEASIBILITY')
            ctx.emit('verification.finished',verdict='VIOLATED',raw_result='SAT',conclusion_gate={'allowed':True})
            row=RunView(t).refresh()['properties'][0]
            self.assertEqual(row['classification'],'FEASIBLE');self.assertIn('不调用被测函数',row['interpretation'])
            self.assertEqual(row['raw_result'],'SAT')

    def test_corrupt_and_truncated_logs_warn_without_claiming_completion(self):
        with tempfile.TemporaryDirectory() as t:
            trace=RunTrace(t,'r');trace.emit('stage.changed',state='VERIFYING')
            with (Path(t)/'events.jsonl').open('ab') as f:f.write(b'not json\n{"partial":')
            view=RunView(t);r=view.refresh();self.assertEqual(r['status'],'OBSERVING');self.assertTrue(r['warnings'])
            write_json_atomic(Path(t)/'checkpoint.json',{'state':'FINISHED','resume_supported':False})
            self.assertEqual(view.refresh()['status'],'OBSERVING')

    def test_result_fallback_keeps_vacuity_errors_and_logging_degradation(self):
        with tempfile.TemporaryDirectory() as t:
            write_json_atomic(Path(t)/'result.json',{'status':'COMPLETED_WITH_ERRORS','mode':'REAL','contracts':[
                {'spec_id':'s','function':'clamp','precondition':{'status':'INFEASIBLE','result':{
                    'property_id':'s.P-FEASIBILITY','kind':'PRECONDITION_FEASIBILITY','verdict':'HOLDS','raw_result':'UNSAT','conclusion_gate':{'allowed':True}}},
                 'properties':[{'property_id':'s.Q1','verdict':'ERROR','conclusion_gate':{'allowed':False}}],
                 'verification':{'verdict':'ERROR'}}],'logging':{'status':'DEGRADED'}})
            r=RunView(t).refresh();self.assertEqual(r['contracts'][0]['verdict'],'ERROR')
            self.assertEqual(r['properties'][0]['classification'],'INFEASIBLE')
            self.assertTrue(any('降级' in w for w in r['warnings']));self.assertEqual(r['evaluation'],'NOT_RUN')

    def test_utf8_can_be_split_across_poll_reads(self):
        with tempfile.TemporaryDirectory() as t:
            trace=RunTrace(t,'utf8');trace.emit('run.started',branch='hoare',message='中文监控')
            with patch('spec_agent.monitor.state.MAX_READ',17):
                view=RunView(t)
                for _ in range(100):r=view.refresh()
            self.assertEqual(view.bad_lines,0);self.assertEqual(r['events'][0]['details']['message'],'中文监控')

    def test_generate_only_has_no_fake_verification_progress(self):
        with tempfile.TemporaryDirectory() as t:
            trace=RunTrace(t,'generate');trace.emit('run.started',branch='hoare',generate_only=True,tool_mode='REAL')
            trace.emit('stage.changed',state='VERIFYING')
            r=RunView(t).refresh();states={s['id']:s['status'] for s in r['stages']}
            self.assertEqual(states['VERIFYING'],'SKIPPED');self.assertEqual(r['properties'],[])
            self.assertEqual(r['branches']['static']['status'],'SKIPPED')

    def test_single_run_and_nested_catalog_do_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);run=root/'batch/case/run';run.mkdir(parents=True)
            write_json_atomic(run/'run_manifest.json',{'run_id':'a'});RunTrace(run,'a')
            registry=RunRegistry(root);rows=registry.catalog()['runs'];self.assertEqual(len(rows),1)
            self.assertEqual(RunRegistry(run,single=True).catalog()['runs'][0]['run_id'],'a')
            outside=root/'outside';outside.mkdir();write_json_atomic(outside/'run_manifest.json',{'run_id':'secret'});RunTrace(outside,'secret')
            watch=root/'watch';watch.mkdir()
            try:(watch/'alias').symlink_to(outside,target_is_directory=True)
            except OSError:return
            self.assertEqual(RunRegistry(watch).catalog()['runs'],[])

    def test_moved_unix_artifacts_are_localized_and_only_observed_logs_allowed(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);old='/old/run';source=old+'/input/source/000/program.c'
            write_json_atomic(root/'run_manifest.json',{'run_id':'moved','input':{'sources':[{'snapshot':source,'original':'program.c'}]}})
            trace=RunTrace(root,'moved');trace.emit('tool.started',command_id='a',argv=['ric3'])
            trace.emit('tool.finished',command_id='a',returncode=1,stdout=old+'/verification/q/ric3/tool.stdout.log',stderr=old+'/verification/q/ric3/tool.stderr.log')
            log=root/'verification/q/ric3/tool.stderr.log';log.parent.mkdir(parents=True);log.write_text('panic detail',encoding='utf-8')
            registry=RunRegistry(root,single=True);key=registry.selected;registry.snapshot(key)
            self.assertEqual(registry.artifact_text(key,'verification/q/ric3/tool.stderr.log')['text'],'panic detail')
            for path in ('../.env','input/secret.stderr.log','.env','/etc/passwd'):
                with self.assertRaises(ValueError):registry.artifact_text(key,path)


class MonitorHttpTests(unittest.TestCase):
    def test_routes_are_read_only_loopback_scoped_and_redacted(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);write_json_atomic(root/'run_manifest.json',{'run_id':'http'})
            trace=RunTrace(root,'http',secrets=('secret-key',));trace.emit('run.started',note='<script>alert(1)</script>',api_key='secret-key')
            trace.emit('tool.started',command_id='t',argv=['ric3'])
            trace.emit('tool.finished',command_id='t',returncode=1,stderr='verification/q/ric3/tool.stderr.log')
            log=root/'verification/q/ric3/tool.stderr.log';log.parent.mkdir(parents=True);log.write_text('secret-key <script>alert(1)</script>')
            server=Monitor(root,port=0,single=True,secrets=('secret-key',)).start()
            try:
                def get(path,**kwargs):return urllib.request.urlopen(urllib.request.Request(server.url.rstrip('/')+path,**kwargs),timeout=5)
                catalog=json.load(get('/api/runs'));key=catalog['runs'][0]['key']
                payload=get('/api/run/'+key).read().decode();self.assertNotIn('secret-key',payload)
                self.assertIn('[REDACTED]',payload)
                raw=get('/api/run/'+key+'/log?path=verification/q/ric3/tool.stderr.log').read().decode()
                self.assertNotIn('secret-key',raw);self.assertIn('[REDACTED]',raw)
                for path,kwargs,code in [('/api/runs',{'method':'POST','data':b'{}'},405),('/.env',{},404),
                        ('/api/runs',{'headers':{'Host':'evil.example'}},403),
                        ('/api/runs',{'headers':{'Origin':'https://evil.example'}},403),
                        ('/api/run/'+key+'/log?path=../.env',{},400)]:
                    with self.assertRaises(urllib.error.HTTPError) as error:get(path,**kwargs)
                    self.assertEqual(error.exception.code,code)
                response=get('/');self.assertIn("frame-ancestors 'none'",response.headers['Content-Security-Policy'])
                self.assertIn('逐属性验证',response.read().decode())
                script=get('/app.js').read().decode();self.assertNotIn('innerHTML',script)
                self.assertNotIn('https://',script)
            finally:server.close()

    def test_monitor_cli_never_loads_credentials_or_tools(self):
        with (tempfile.TemporaryDirectory() as t,
              patch('spec_agent.cli.load_config',side_effect=AssertionError('config access')),
              patch('spec_agent.monitor.server.serve',return_value=0) as serve):
            self.assertEqual(main(['monitor','--run',t,'--port','0']),0);self.assertTrue(serve.called)


@unittest.skipIf(os.name=='nt','Verification pipeline requires POSIX/WSL')
class MonitorPipelineTests(unittest.TestCase):
    def test_ui_lifecycle_preserves_violation_exit_code(self):
        from spec_agent.config import Config
        with (tempfile.TemporaryDirectory() as t,
              patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin','source_violated')}),
              patch('spec_agent.cli.load_config',return_value=Config(tool_mode='MOCK')),
              patch('spec_agent.monitor.server.Monitor') as monitor,
              contextlib.redirect_stdout(io.StringIO())):
            monitor.return_value.start.return_value=monitor.return_value
            status=main(['run','--source',str(ROOT/'examples/clamp/program.c'),
                '--requirements',str(ROOT/'examples/clamp/requirements.md'),'--branch','hoare',
                '--llm-fixture',str(ROOT/'examples/clamp/llm_fixture.json'),'--output',str(Path(t)/'runs'),'--ui','--ui-no-open'])
            self.assertEqual(status,1)
            monitor.return_value.attach.assert_called_once();monitor.return_value.wait.assert_called_once()
            monitor.return_value.close.assert_called_once()

    def test_observation_and_observer_failure_do_not_change_verification(self):
        from spec_agent.controller import run
        from spec_agent.config import Config
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin','source_holds')}):
            def broken(_):raise RuntimeError('UI unavailable')
            root,result=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',Config(tool_mode='MOCK'),
                branch='hoare',fixture=ROOT/'examples/clamp/llm_fixture.json',output=Path(t)/'runs',on_run_created=broken)
            self.assertEqual(result['contracts'][0]['verification']['verdict'],'HOLDS')
            before={p:sha256_file(p) for p in root.rglob('*') if p.is_file()}
            registry=RunRegistry(root,single=True);r=registry.snapshot(registry.selected)
            self.assertEqual(r['contracts'][0]['verdict'],'HOLDS')
            self.assertEqual(next(p for p in r['properties'] if p['kind']=='PRECONDITION_FEASIBILITY')['classification'],'FEASIBLE')
            self.assertEqual(before,{p:sha256_file(p) for p in root.rglob('*') if p.is_file()})
