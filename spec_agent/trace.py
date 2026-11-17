"""Bounded run-scoped observation; proof evidence lives in separate artifacts."""
import json
import re
import sys
import threading
import time
from pathlib import Path
from .artifacts import encode, utc_now

_SECRET_FIELDS = {'authorization', 'api_key', 'apikey', 'access_token', 'refresh_token', 'password', 'secret'}


def redact(value, secrets=()):
    """Redact decoded values, so JSON escaping cannot hide a configured secret."""
    if isinstance(value, str):
        variants = {v for s in secrets if s for v in (s,json.dumps(s)[1:-1],json.dumps(s,ensure_ascii=False)[1:-1])}
        for secret in sorted(variants,key=len,reverse=True):
            value = value.replace(secret, '[REDACTED]')
        return value
    if isinstance(value, dict):
        return {redact(k, secrets): '[REDACTED]' if str(k).lower() in _SECRET_FIELDS
                else redact(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, secrets) for v in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact(encode(value), secrets)


def format_event(record):
    context = ' '.join(f'{k}={v}' for k, v in record.get('context', {}).items())
    header = (f"[{record['sequence']:04d}] {record['timestamp']} "
              f"{record.get('level', 'INFO')} {record['event']} {context}").rstrip()
    # JSON encoding escapes control characters from source/model strings.
    header = header.replace('\r', '\\r').replace('\n', '\\n').replace('\x1b', '\\u001b')
    return header+'\n'+''.join('  '+line+'\n' for line in
                              json.dumps(record['details'], ensure_ascii=False, indent=2).splitlines())


class BoundTrace:
    def __init__(self, parent, context):
        self.parent, self.context = parent, context

    def bind(self, **context):
        return BoundTrace(self.parent, {**self.context, **context})

    def emit(self, event, *, level='INFO', **details):
        self.parent._emit(event, level, self.context, details)


class RunTrace:
    def __init__(self, root, run_id, secrets=(), max_bytes=32*1024*1024):
        if max_bytes < 1024: raise ValueError('Log limit must be at least 1024 bytes')
        self.root, self.run_id = Path(root).resolve(), run_id
        self.secrets, self.max_bytes = tuple(s for s in secrets if s), max_bytes
        self.lock = threading.RLock()
        self.sequence, self.started = 0, time.monotonic()
        self.sizes = {'events.jsonl': 0, 'process.log': 0}
        self.disabled, self.errors = set(), []
        self.dropped_events = 0
        self.warned = False
        for name in self.sizes:
            try:
                with (self.root/name).open('xb'): pass
                (self.root/name).chmod(0o600)
            except OSError as exc:
                self._disable(name, type(exc).__name__)

    def bind(self, **context):
        return BoundTrace(self, context)

    def emit(self, event, *, level='INFO', **details):
        self._emit(event, level, {}, details)

    def _disable(self, sink, reason):
        self.disabled.add(sink)
        self.errors.append({'sink': sink, 'reason': reason})
        if not self.warned:
            self.warned = True
            try:
                print('WARNING: observation log incomplete; see result.json logging status.', file=sys.stderr)
            except OSError:
                pass

    def _relative(self, value):
        if isinstance(value, str) and value.startswith(str(self.root)+'/'):
            return value[len(str(self.root))+1:]
        if isinstance(value, dict): return {k: self._relative(v) for k, v in value.items()}
        if isinstance(value, list): return [self._relative(v) for v in value]
        return value

    def _emit(self, event, level, context, details):
        with self.lock:
            self.sequence += 1
            if len(self.disabled) == 2:
                self.dropped_events += 1
                return
            try:
                if not re.fullmatch(r'[a-z][a-z0-9_.]*', event):
                    raise ValueError('Invalid event name')
                if level not in ('DEBUG','INFO','WARNING','ERROR'): raise ValueError('Invalid log level')
                # Common correlation identifiers also remain in details for v1 consumers.
                context = {**context, **{k: details[k] for k in
                           ('branch','function_id','spec_id','clause_id','property_id','job_id','attempt_id') if k in details}}
                record = self._relative(redact(dict(
                    schema_version=2, run_id=self.run_id, sequence=self.sequence,
                    timestamp=utc_now(), elapsed_ms=round((time.monotonic()-self.started)*1000,3),
                    level=level, event=event, context=context, details=details), self.secrets))
                payloads = {'events.jsonl': json.dumps(record,ensure_ascii=False,allow_nan=False)+'\n',
                            'process.log': format_event(record)}
                encoded = {k: v.encode('utf-8') for k,v in payloads.items()}
            except (TypeError, ValueError, RecursionError, UnicodeError):
                self.dropped_events += 1
                if not any(e['reason']=='SERIALIZATION_FAILED' for e in self.errors):
                    self.errors.append({'sink':'event','reason':'SERIALIZATION_FAILED'})
                return
            lost = False
            for name, data in encoded.items():
                if name in self.disabled:
                    lost = True
                    continue
                if self.sizes[name]+len(data) > self.max_bytes:
                    self._disable(name, 'SIZE_LIMIT_EXCEEDED'); lost = True
                    continue
                try:
                    with (self.root/name).open('ab') as stream: stream.write(data)
                    self.sizes[name] += len(data)
                except OSError as exc:
                    self._disable(name, type(exc).__name__); lost = True
            if lost: self.dropped_events += 1

    def status(self):
        with self.lock:
            return {'status':'DEGRADED' if self.errors else 'COMPLETE', 'schema_version':2,
                    'events':'events.jsonl','human_readable':'process.log',
                    'attempted_events':self.sequence,'dropped_events':self.dropped_events,
                    'bytes':dict(self.sizes),'max_bytes_per_file':self.max_bytes,'errors':list(self.errors)}


def read_events(path, *, function_id=None, spec_id=None, property_id=None, level=None, event=None):
    """Stream/filter a saved run. A crash-truncated final line is explicitly rejected."""
    from .errors import AgentError
    wanted = dict(function_id=function_id,spec_id=spec_id,property_id=property_id)
    with Path(path).open(encoding='utf-8') as stream:
        for number, line in enumerate(stream, 1):
            try:
                if not line.endswith('\n'): raise ValueError()
                record = json.loads(line)
                if not isinstance(record,dict) or not all(k in record for k in ('event','details','sequence','timestamp')): raise ValueError()
                if type(record['sequence']) is not int or record['sequence']<1: raise ValueError()
                if not isinstance(record['timestamp'],str) or not isinstance(record['event'],str): raise ValueError()
                context = record.get('context',record['details'])
                if not isinstance(context,dict) or not isinstance(record['details'],dict): raise ValueError()
            except (ValueError, TypeError):
                raise AgentError('LOG_INVALID',f'Invalid or incomplete event at line {number}') from None
            if any(v is not None and context.get(k,record['details'].get(k)) != v for k,v in wanted.items()): continue
            if level and record.get('level','INFO') != level: continue
            if event and record['event'] != event: continue
            yield record
