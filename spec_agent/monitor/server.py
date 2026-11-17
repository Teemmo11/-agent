"""Loopback-only, read-only HTTP monitor. No command/file-write endpoints."""
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
from .state import RunRegistry

ASSETS=Path(__file__).with_name('assets')


class Monitor:
    def __init__(self,root,*,port=8765,single=False,secrets=(),focused=False,show_pq=False):
        self.registry=RunRegistry(root,single=single,secrets=secrets,show_pq=show_pq)
        self.registry.focused=focused
        self.lock=threading.RLock();owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def reply(self,status,value,kind='application/json; charset=utf-8'):
                data=json.dumps(value,ensure_ascii=False).encode('utf-8') if kind.startswith('application/json') else value
                self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(data)))
                self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
                self.send_header('Referrer-Policy','no-referrer')
                self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
                self.end_headers()
                try:self.wfile.write(data)
                except (BrokenPipeError,ConnectionResetError):pass
            def do_GET(self):
                allowed={f'127.0.0.1:{owner.port}',f'localhost:{owner.port}'}
                if self.headers.get('Host') not in allowed:
                    self.reply(403,{'error':'Loopback host required'});return
                origin=self.headers.get('Origin')
                if origin and origin not in {f'http://{h}' for h in allowed}:
                    self.reply(403,{'error':'Same origin required'});return
                if self.headers.get('Sec-Fetch-Site')=='cross-site':
                    self.reply(403,{'error':'Cross-site requests are not supported'});return
                request=urlsplit(self.path);path=request.path
                try:
                    if path in ('/','/app.js','/style.css'):
                        name={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}[path]
                        kind={'index.html':'text/html; charset=utf-8','app.js':'text/javascript; charset=utf-8','style.css':'text/css; charset=utf-8'}[name]
                        self.reply(200,(ASSETS/name).read_bytes(),kind);return
                    with owner.lock:
                        if path=='/api/runs':value=owner.registry.catalog()
                        elif path.startswith('/api/run/'):
                            parts=path.strip('/').split('/')
                            if len(parts)==3:value=owner.registry.snapshot(parts[2])
                            elif len(parts)==4 and parts[3]=='log':
                                relative=parse_qs(request.query).get('path',[''])[0]
                                value=owner.registry.artifact_text(parts[2],relative)
                            else:raise KeyError(path)
                        else:raise KeyError(path)
                    self.reply(200,value)
                except KeyError:self.reply(404,{'error':'Unknown run or route'})
                except (ValueError,OSError):self.reply(400,{'error':'Artifact is unavailable or outside the allowed run'})
                except Exception:self.reply(500,{'error':'Unable to read observation data; verification is unaffected'})
            def do_POST(self):self.reply(405,{'error':'Read-only monitor'})
            do_PUT=do_POST
            do_DELETE=do_POST
        self.http=ThreadingHTTPServer(('127.0.0.1',port),Handler)
        self.port=self.http.server_address[1];self.url=f'http://127.0.0.1:{self.port}/'
        self.thread=None

    def start(self,*,open_browser=False):
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True,name='spec-agent-monitor');self.thread.start()
        if open_browser:threading.Thread(target=lambda:webbrowser.open(self.url),daemon=True).start()
        return self

    def attach(self,root):
        with self.lock:self.registry.attach(root)

    def wait(self):
        try:
            while self.thread and self.thread.is_alive():self.thread.join(.5)
        except KeyboardInterrupt:pass

    def close(self):
        if self.thread:self.http.shutdown()
        self.http.server_close()
        if self.thread:self.thread.join(timeout=2)


def serve(root,*,port=8765,single=False,open_browser=False,show_pq=False):
    server=Monitor(root,port=port,single=single,show_pq=show_pq).start(open_browser=open_browser)
    print('Monitor:',server.url,flush=True)
    print('只读监控已启动；Ctrl+C 关闭。',flush=True)
    try:server.wait()
    finally:server.close()
    return 0
