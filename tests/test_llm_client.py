import json
import tempfile
import threading
import unittest
from http.server import HTTPServer,BaseHTTPRequestHandler
from pathlib import Path
from spec_agent.config import Config,load_config
from spec_agent.llm.client import OpenAIClient
from spec_agent.errors import AgentError

class ClientTests(unittest.TestCase):
    def test_compatible_http_and_redaction(self):
        captured=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                captured.append((self.path,self.headers.get('Authorization'),json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                self.send_response(200);self.end_headers()
                self.wfile.write(json.dumps({'choices':[{'finish_reason':'stop','message':{'content':'secret-test-token'}}]}).encode())
        server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as t:
                config=Config(f'http://127.0.0.1:{server.server_port}/v1','ds v4.1 flash','secret-test-token')
                value=OpenAIClient(config).complete([{'role':'user','content':'hello'}],Path(t))
                self.assertEqual(value,'[REDACTED]')
                self.assertNotIn('secret-test-token',(Path(t)/'response.raw.json').read_text())
            self.assertEqual(captured[0][0],'/v1/chat/completions')
            self.assertEqual(captured[0][1],'Bearer secret-test-token')
            self.assertEqual(captured[0][2]['model'],'ds v4.1 flash')
        finally: server.shutdown();server.server_close();thread.join()
    def test_config_repr_and_env(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'.env';path.write_text('LLM_BASE_URL=https://example.test/v1\nLLM_MODEL="ds v4.1 flash"\nLLM_API_KEY=secret-test-token\n')
            c=load_config(path);self.assertFalse(c.llm_issues());self.assertNotIn('secret-test-token',repr(c))
    def test_insecure_remote_url_rejected(self):
        self.assertIn('LLM_BASE_URL_INVALID',Config('http://remote.test/v1','m','k').llm_issues())

class ResponseObservationTests(unittest.TestCase):
    def respond(self, raw, directory):
        from unittest.mock import MagicMock, patch
        response=MagicMock()
        response.__enter__.return_value.read.return_value=raw
        opener=MagicMock();opener.open.return_value=response
        with patch('spec_agent.llm.client.urllib.request.build_opener',return_value=opener):
            return OpenAIClient(Config('https://example.test/v1','test-model','secret"\\key')).complete([],directory)

    def test_escaped_secret_redacted_after_json_decode(self):
        secret='secret"\\key'
        raw=json.dumps({'choices':[{'finish_reason':'stop','message':{'content':secret}}],
                        'usage':{'prompt_tokens':12,'completion_tokens':5,'total_tokens':17,'extra':'ignored'}}).encode()
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            self.assertEqual(self.respond(raw,root),'[REDACTED]')
            saved=json.loads((root/'response.raw.json').read_text())
            self.assertEqual(saved['choices'][0]['message']['content'],'[REDACTED]')
            metadata=json.loads((root/'response.metadata.json').read_text())
            self.assertEqual(metadata['usage'],{'prompt_tokens':12,'completion_tokens':5,'total_tokens':17})

    def test_truncation_keeps_finish_reason_usage_and_partial_output(self):
        raw=json.dumps({'choices':[{'finish_reason':'length','message':{'content':'{"partial":'}}],
                        'usage':{'completion_tokens':30}}).encode()
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            with self.assertRaises(AgentError): self.respond(raw,root)
            metadata=json.loads((root/'response.metadata.json').read_text())
            self.assertEqual(metadata['finish_reason'],'length')
            self.assertEqual(metadata['usage']['completion_tokens'],30)
            self.assertEqual((root/'response.txt').read_text(),'{"partial":')

    def test_malformed_provider_json_has_no_unsafe_raw_body(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            with self.assertRaises(AgentError): self.respond(b'{"broken secret',root)
            self.assertEqual(json.loads((root/'response.raw.json').read_text()),{'omitted':'MALFORMED_PROVIDER_JSON'})
