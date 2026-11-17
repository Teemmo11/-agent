"""Shared request and query budget with per-call disk evidence."""
from threading import Lock
from time import perf_counter
from pathlib import Path
import hashlib
import json

from ..artifacts import write_json_atomic
from ..errors import AgentError
from ..evaluation.models import Budget
from ..ir_ab.semantics import canon, digest
from ..llm.client import OpenAIClient
from ..trace import redact
from ..t3t4.input import read_json


class Ledger:
    def __init__(self, limits):
        limits.validate()
        self.budget = Budget(limits)
        self.requests = 0
        self.fixtures = 0
        self.lock = Lock()

    def snapshot(self):
        with self.lock:
            return {**self.budget.snapshot(), 'online_requests': self.requests, 'fixture_requests': self.fixtures}

    def query(self, case):
        with self.lock:
            return self.budget.reserve('query', case)

    def call(self, case, size, fixture):
        with self.lock:
            limits = self.budget.limits
            if size > limits.input_tokens or not self.budget.reserve('llm', case, size + limits.output_tokens):
                raise AgentError('LLM_BUDGET_EXHAUSTED', 'Shared request or token budget exhausted')
            if fixture:
                self.fixtures += 1
            else:
                self.requests += 1
            return self.budget.calls

    def charge(self, metadata):
        with self.lock:
            self.budget.charge(metadata)


class Gateway:
    def __init__(self, case, ledger, *, config=None, fixture=None):
        self.mode = 'ONLINE' if config else 'FIXTURE' if fixture is not None else 'OFFLINE'
        self.config = config
        self.client = OpenAIClient(config) if config else None
        self.case = case
        self.ledger = ledger
        self.responses = {key: iter(values) for key, values in (fixture or {}).items()}

    def call(self, stage, messages, directory):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        secrets = (self.config.api_key,) if self.config else ()
        record = {'stage': stage, 'mode': self.mode, 'number': None, 'status': 'NOT_RUN',
                  'request_sha256': digest(redact(messages, secrets))}
        if self.config:
            record['requested_model'] = redact(self.config.model, secrets)
            record['endpoint_sha256'] = hashlib.sha256(self.config.base_url.encode()).hexdigest()
        write_json_atomic(directory / 'request.json', redact(messages, secrets))
        start = perf_counter()
        try:
            if self.mode == 'OFFLINE':
                raise AgentError('MODEL_NOT_ENABLED', 'Choose --fixture or --online')
            if self.config and self.config.llm_issues():
                raise AgentError('LLM_CONFIG_MISSING', 'Incomplete or invalid model configuration')
            if self.mode == 'FIXTURE':
                try:
                    payload = next(self.responses.get(stage, iter(())))
                except StopIteration:
                    raise AgentError('FIXTURE_EXHAUSTED', 'No fixture response for this stage') from None
            size = len(json.dumps(messages, ensure_ascii=False).encode('utf-8'))
            record['number'] = self.ledger.call(self.case, size, self.mode == 'FIXTURE')
            record['input_bytes_estimate'] = size
            record['output_limit'] = self.ledger.budget.limits.output_tokens
            if self.client:
                text = self.client.complete(messages, directory, max_output_tokens=record['output_limit'],
                                            distinguish_timeout=True)
            else:
                text = payload if isinstance(payload, str) else canon(payload)
            text = redact(text, secrets)
            (directory / 'response.txt').write_text(text, encoding='utf-8')
            record.update(status='RESPONSE_RECEIVED', response_sha256=digest(text))
            return text
        except AgentError as exc:
            record.update(status='ERROR' if record['number'] is not None else 'NOT_RUN', reason=exc.code)
            raise
        finally:
            metadata = directory / 'response.metadata.json'
            if metadata.is_file():
                row = read_json(metadata)
                record['provider'] = row
                self.ledger.charge(row)
            record['elapsed_ms'] = round((perf_counter()-start)*1000, 3)
            write_json_atomic(directory / 'call.json', record)
