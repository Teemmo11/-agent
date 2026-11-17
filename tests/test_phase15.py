"""Fault injection and audit regression tests. Never real C correctness claims."""
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from http.server import HTTPServer,BaseHTTPRequestHandler
from spec_agent.config import Config
from spec_agent.controller import run
from spec_agent.preflight import doctor,pinned_command,probe_semantics
from spec_agent.errors import AgentError
from spec_agent.verification.audit import audit_run
from helpers import ROOT,fake_tools

class IntegrationBoundaryTests(unittest.TestCase):
    def test_doctor_missing_environment(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':''}):
            r=doctor(Config(),Path(t),probe_tools=True,check_llm=True)
            self.assertFalse(r['ready']);self.assertEqual(r['llm']['connection_status'],'BLOCKED')
            self.assertEqual(r['semantic_probe']['status'],'BLOCKED')
            self.assertEqual(set(r['llm']['issues']),{'LLM_BASE_URL_MISSING','LLM_MODEL_MISSING','LLM_API_KEY_MISSING'})
    def test_probe_protocol_with_explicit_test_doubles(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin')}):
            c=Config(tool_mode='MOCK');caps=doctor(c,Path(t)/'doctor')
            self.assertEqual(caps['ric3_profile'],'btor-ric3-check-portfolio')
            result=probe_semantics(c,Path(t)/'probe',caps)
            self.assertEqual(result['status'],'PASSED')
            self.assertEqual([x.get('raw') for x in result['checks'][:2]],['SAT','UNSAT'])
    def test_real_refuses_fake_tools(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin')}):
            caps=doctor(Config(),Path(t)/'doctor');self.assertFalse(caps['ready']);self.assertTrue(caps['mock_detected'])
            root,r=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',Config(),output=Path(t)/'run')
            self.assertEqual(r['failures'][0]['code'],'MOCK_IN_REAL_RUN');self.assertFalse((root/'verification').exists())
    def test_real_refuses_fixture_before_generation(self):
        with tempfile.TemporaryDirectory() as t:
            _,r=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',Config(),output=t,
                    fixture=ROOT/'examples/clamp/llm_fixture.json',require_real=True)
            self.assertEqual(r['failures'][0]['code'],'MOCK_IN_REAL_RUN')
    def test_executable_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin')}):
            c=Config(tool_mode='MOCK');caps=doctor(c,Path(t)/'doctor')
            Path(caps['tools']['cbmc']['executable']).write_text('# changed\n')
            with self.assertRaises(AgentError) as e:pinned_command(['cbmc','--help'],caps,c)
            self.assertEqual(e.exception.code,'TOOL_IDENTITY_CHANGED')
    def test_spec_tamper_and_real_audit_rejection(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin')}):
            root,r=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',Config(tool_mode='MOCK'),output=Path(t)/'runs',fixture=ROOT/'examples/clamp/llm_fixture.json',branch='hoare')
            self.assertEqual(audit_run(root,require_real=False)['status'],'PASSED')
            self.assertIn('NON_REAL_RUN',audit_run(root)['errors'])
            sem=Path(r['contracts'][0]['provenance']['semantic_spec']);sem.write_text(sem.read_text()+'\n')
            a=audit_run(root,require_real=False)
            self.assertEqual(a['status'],'FAILED');self.assertTrue(any('HASH_MISMATCH' in x for x in a['errors']))
    def test_bad_formal_candidates_and_harness(self):
        cases=[('imaginary > 0','UNKNOWN_IDENTIFIER',False),('result + 1 > low','FORMALIZATION_UNSUPPORTED',False),
               ('result >= low','UNSUPPORTED_HARNESS',True)]
        for expr,code,pointer in cases:
            with self.subTest(code=code),tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':''}):
                fixture=json.loads((ROOT/'examples/clamp/llm_fixture.json').read_text())
                fixture['clamp']['function_spec']['post_conditions'][0]['formal_candidate']=expr
                source=ROOT/'examples/clamp/program.c'
                if pointer:
                    source=Path(t)/'program.c';source.write_text('int clamp(int *x, int low, int high) { return low; }')
                    fixture['clamp']['function_spec']['function']['signature']='int clamp(int *x, int low, int high)'
                f=Path(t)/'fixture.json';f.write_text(json.dumps(fixture))
                _,r=run([source],ROOT/'examples/clamp/requirements.md',Config(),output=Path(t)/'runs',fixture=f,branch='hoare')
                self.assertEqual(r['contracts'][0]['verification']['error']['code'],code)
                self.assertFalse(r['contracts'][0]['conclusion_gate']['allowed'])
    def test_invalid_llm_json_through_actual_http(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(200);self.end_headers()
                self.wfile.write(json.dumps({'choices':[{'finish_reason':'stop','message':{'content':'this is invalid JSON'}}]}).encode())
        server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':''}):
                c=Config(f'http://127.0.0.1:{server.server_port}/v1','test-model','test-key')
                root,r=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',c,output=t,branch='hoare')
                self.assertEqual(r['failures'][0]['error']['code'],'LLM_RESPONSE_INVALID')
                self.assertFalse(r['contracts']);self.assertTrue(list(root.glob('generation/llm/functions/*/response.raw.json')))
        finally:server.shutdown();server.server_close();thread.join()
    def test_tool_failure_codes_and_gate(self):
        expected={'build_fail':('ERROR','BTOR_BUILD_FAILED'),'invalid':('ERROR','BTOR_INVALID'),
                  'timeout':('UNKNOWN','RIC3_TIMEOUT'),'unknown':('UNKNOWN',None)}
        for scenario,(verdict,code) in expected.items():
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin',scenario)}):
                _,r=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',
                    Config(tool_mode='MOCK',tool_timeout=.25 if scenario=='timeout' else 5),output=Path(t)/'runs',fixture=ROOT/'examples/clamp/llm_fixture.json',branch='hoare')
                q=r['contracts'][0]['properties'][0]
                self.assertEqual(q['verdict'],verdict);self.assertFalse(q['conclusion_gate']['allowed'])
                if code:self.assertEqual(q['error']['code'],code)
