"""Local HTTP stub only. No external endpoint or real provider credentials."""
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
from spec_agent.config import Config
from spec_agent.artifacts import write_json_atomic
from spec_agent.evaluation.controller import evaluate
from spec_agent.evaluation.audit import audit_evaluation
from evaluation_helpers import make_parent,review_response


class LocalReviewTests(unittest.TestCase):
    def test_bounded_request_and_strict_evidence_review(self):
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'parent');value,_,_=review_response(parent)
            requests=[]
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_POST(self):
                    requests.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                    body=json.dumps({'choices':[{'finish_reason':'stop','message':{'content':json.dumps(value)}}],
                                     'usage':{'prompt_tokens':100,'completion_tokens':200},'model':'local-stub'}).encode()
                    self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                root,result=evaluate(parent,Config(base_url=f'http://127.0.0.1:{server.server_port}',model='local-stub',api_key='LOCAL_TEST_SECRET'),
                                     reviewer='real',output=Path(t)/'eval')
            finally:server.shutdown();server.server_close();thread.join()
            self.assertEqual(len(requests),1);self.assertEqual(requests[0]['max_tokens'],2048)
            self.assertEqual(result['execution_status'],'COMPLETED');self.assertEqual(audit_evaluation(root)['status'],'PASSED')
            for p in root.rglob('*'):
                if p.is_file():self.assertNotIn(b'LOCAL_TEST_SECRET',p.read_bytes())

    def test_bad_response_retries_do_not_escape_the_shared_budget(self):
        from unittest.mock import patch
        from spec_agent.evaluation.models import Limits
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'parent')
            with patch('spec_agent.llm.client.OpenAIClient.complete',return_value='not json') as client:
                root,result=evaluate(parent,Config(),reviewer='real',output=Path(t)/'eval',limits=Limits(llm_calls=1))
            self.assertEqual(client.call_count,1);self.assertEqual(result['execution_status'],'PARTIAL')
            self.assertEqual(result['budget']['llm_calls'],1);self.assertEqual(audit_evaluation(root)['status'],'PASSED')
