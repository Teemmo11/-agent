from dataclasses import dataclass, field, asdict
from typing import Literal

Verdict = Literal['HOLDS', 'VIOLATED', 'VACUOUS', 'UNKNOWN', 'ERROR']

@dataclass
class Parameter:
    name: str
    type: str

@dataclass
class FunctionContext:
    function_id: str
    name: str
    signature: str
    return_type: str
    parameters: list[Parameter]
    source_file: str
    start_line: int
    end_line: int
    body: str
    source_sha256: str
    callers: list[dict] = field(default_factory=list)
    callees: list[dict] = field(default_factory=list)
    caller_expectations: list[dict] = field(default_factory=list)
    requirement_refs: list[str] = field(default_factory=list)
    storage: list[str] = field(default_factory=list)
    harness_issues: list[str] = field(default_factory=list)

@dataclass
class ProgramModel:
    functions: list[FunctionContext]
    callsites: list[dict]
    unresolved: list[dict]
    order: list[str]

@dataclass
class FormalEnsures:
    clause_id: str
    expr: str
    guard_expr: str | None

@dataclass
class FormalContract:
    contract_id: str
    source_spec_id: str
    function_id: str
    precondition_expr: str
    ensures: list[FormalEnsures]
    required_snapshots: list[str]
    source_sha256: str
    requirements_sha256: str

@dataclass
class VerificationJob:
    job_id: str
    kind: str
    source_files: list[str]
    entry: str
    spec_id: str
    property_id: str
    cbmc_property_id: str | None = None
    harness_file: str | None = None
    assertion_line: int | None = None
    generation_flags: list[str] = field(default_factory=list)
    source_hashes: dict[str, str] = field(default_factory=dict)
    provenance: dict = field(default_factory=dict)

@dataclass
class CommandResult:
    argv: list[str]
    executable: str | None
    cwd: str
    started_at: str
    ended_at: str
    duration_seconds: float
    returncode: int | None
    timed_out: bool
    stdout_path: str
    stderr_path: str
    stdout_sha256: str
    stderr_sha256: str
    spawn_error: str | None = None
    resource_limit: str | None = None
    def to_dict(self): return asdict(self)
    @property
    def ok(self):
        return self.returncode == 0 and not (self.timed_out or self.spawn_error or self.resource_limit)
