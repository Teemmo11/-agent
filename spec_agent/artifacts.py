import hashlib
import json
import os
import re
import tempfile
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path


def utc_now(): return datetime.now(timezone.utc).isoformat()
def sha256_file(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def encode(value):
    if is_dataclass(value): return asdict(value)
    if isinstance(value, Path): return str(value)
    raise TypeError(type(value).__name__)

def write_json_atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(value, f, default=encode, indent=2, ensure_ascii=False)
            f.write('\n')
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)

class ArtifactStore:
    def __init__(self, output_root):
        self.run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:12]
        self.root = Path(output_root).resolve() / self.run_id
        self.root.mkdir(parents=True, mode=0o700)
    def write(self, name, value): write_json_atomic(self.root / name, value)
    def snapshot(self, sources, requirements):
        paths, records = [], []
        for i, source in enumerate(sources):
            source = Path(source)
            if not source.is_file() or source.is_symlink(): raise ValueError('Require regular source files')
            target = self.root / 'input' / 'source' / f'{i:03d}' / source.name
            target.parent.mkdir(parents=True)
            raw_source=source.read_bytes()
            # No unsnapshotted headers or compiler-dependent predefined macros.
            from .analysis.functions import clean_comments
            from .errors import AgentError
            if re.search(r'^\s*#',clean_comments(raw_source.decode('utf-8')),re.M):
                raise AgentError('INPUT_DEPENDENCY_UNSUPPORTED','Provide self-contained C without preprocessor directives; headers/macros are not silently expanded')
            target.write_bytes(raw_source)
            paths.append(target)
            records.append({'original': str(source.resolve()), 'snapshot': str(target), 'sha256': sha256_file(target)})
        raw = Path(requirements).read_bytes()
        req = self.root / 'input/requirements.md'
        req.write_bytes(raw)
        info = {'sources': records, 'source_sha256': digest(json.dumps([(r['original'], r['sha256']) for r in records])),
                'requirements_sha256': sha256_file(req)}
        self.write('run_manifest.json', {'run_id': self.run_id, 'created_at': utc_now(), 'input': info,
                    'evaluation': {'status': 'NOT_RUN'}, 'resume_supported': False})
        return paths, req, info
