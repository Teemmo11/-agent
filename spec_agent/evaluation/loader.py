"""Read-only parent loading, relocation and independent integrity validation."""
import json
import re
from dataclasses import asdict
from pathlib import Path,PurePosixPath,PureWindowsPath
from ..artifacts import digest,sha256_file
from ..errors import AgentError
from ..llm.parser import strict_json,parse_response
from ..requirements.parser import parse_requirements
from ..analysis.functions import CAnalyzer
from ..spec.formalizer import formalize


def pure_path(value):
    return PureWindowsPath(value) if '\\' in str(value) or re.match(r'^[A-Za-z]:[\\/]',str(value)) else PurePosixPath(value)


class ParentRun:
    def __init__(self,root):
        self.root=Path(root).resolve();self.dependencies={};self.expected={};self.missing=[]
        self.manifest=self.read('run_manifest.json');self.report=self.read('result.json')
        try:
            sources=self.manifest['input']['sources']
            self.original=pure_path(sources[0]['snapshot']).parents[3]
            if self.report.get('input')!=self.manifest['input']:self.fail('Input summaries differ')
            self.info=self.manifest['input']
            if self.manifest.get('evaluation')!={'status':'NOT_RUN'}:self.fail('Not a Phase 1 run')
            self.source_paths=[]
            for row in sources:
                path=self.path(row['snapshot']);self.check(path,row['sha256']);self.source_paths.append(path)
            combined=digest(json.dumps([(r['original'],r['sha256']) for r in sources]))
            if combined!=self.info['source_sha256']:self.fail('Source collection hash mismatch')
            self.check(self.path('input/requirements.md'),self.info['requirements_sha256'])
            self.requirements_text=self.text('input/requirements.md')
            if not self.requirements_text.strip():raise AgentError('REQUIREMENTS_EMPTY','No requirement text available for assessment')
            self.requirements=parse_requirements(self.requirements_text)
            # Check every declared evidence dependency, even for UNKNOWN jobs.
            for path in sorted((self.root/'verification').rglob('evidence_hashes.json')):
                self.safe(path)
                for ref,checksum in self.read(path).items():
                    target=self.path(ref)
                    if str(target) in self.expected and self.expected[str(target)]!=checksum:self.fail('Conflicting evidence hashes')
                    self.expected[str(target)]=checksum;self.check(target,checksum)
            self.program=CAnalyzer().analyze(self.source_paths)
            self.functions={f.function_id:f for f in self.program.functions}
            self.specs=[];self.formals={};self.verified={}
            rows={c['spec_id']:c for c in self.report.get('contracts',[])}
            for path in sorted((self.root/'specs/semantic').glob('*.json')):
                spec=self.read(path);sid=spec['spec_id'];function=self.functions.get(spec['function_id'])
                if sid!=path.stem or not function:self.fail('Specification/function identity mismatch')
                for key in ('source_sha256','requirements_sha256'):
                    if spec.get(key)!=self.info[key]:self.fail('Specification input hash mismatch')
                semantic={'function_spec':spec['function_spec'],'callee_expectations':spec['callee_expectations']}
                # Restore only declared expectation IDs for reference validation.
                function.caller_expectations=[{'expectation_id':x} for x in spec.get('caller_expectation_refs',[])]
                parse_response(json.dumps(semantic),function,self.requirements,self.program)
                row=rows.get(sid,{})
                provenance=row.get('provenance',{})
                if provenance:
                    self.check(path,provenance['semantic_spec_sha256'])
                else:
                    raw_path='generation/llm/functions/'+function.function_id+'/response.txt'
                    if not self.path(raw_path).is_file():self.fail('Unbound generated specification')
                    raw=strict_json(self.text(raw_path))
                    if raw!=semantic:self.fail('Generated response/spec mismatch')
                self.specs.append(spec);self.verified[sid]=row
                formal_ref='specs/formal/'+sid+'.json'
                if self.path(formal_ref).exists():
                    formal=self.read(formal_ref)
                    if asdict(formalize(spec,function,self.info))!=formal:self.fail('Formal specification mismatch')
                    self.formals[sid]=formal
                else:self.missing.append({'spec_id':sid,'kind':'FORMAL_NOT_AVAILABLE'})
                for prop in [row.get('precondition',{}).get('result'),*row.get('properties',[])]:
                    if not prop:continue
                    disk=self.read(self.path(prop['evidence_manifest']).parent/'result.json')
                    for key in ('property_id','verdict','raw_result','conclusion_gate','model_sha256','execution_refs'):
                        if prop.get(key)!=disk.get(key):self.fail('Property summary differs from evidence')
            if len({s['spec_id'] for s in self.specs})!=len(self.specs):self.fail('Duplicate specification identity')
            if not set(rows)<={s['spec_id'] for s in self.specs}:self.fail('Contract summary references missing specification')
            # Rebuild derived caller expectations from the checked semantic specs.
            for f in self.functions.values():f.caller_expectations=[]
            for spec in self.specs:
                for value in spec.get('callee_expectations',[]):
                    site=next(s for s in self.program.callsites if s['callsite_id']==value['callsite_id'])
                    self.functions[site['callee_function']].caller_expectations.append(
                        {**value,'expectation_id':'EXP-'+site['callsite_id'],'source_spec_id':spec['spec_id'],
                         'origin':'GENERATED_EXPECTATION_NOT_GROUND_TRUTH'})
            for f in self.functions.values():
                for issue in f.harness_issues:self.missing.append({'function_id':f.function_id,'kind':issue})
                if f.function_id not in {s['function_id'] for s in self.specs}:
                    self.missing.append({'function_id':f.function_id,'kind':'SEMANTIC_SPEC_NOT_AVAILABLE'})
            for spec in self.specs:
                known={e['expectation_id'] for e in self.functions[spec['function_id']].caller_expectations}
                if not set(spec.get('caller_expectation_refs',[]))<=known:self.fail('Unbound propagated expectation')
            self.toolchain=self.optional('toolchain_manifest.json',{})
            self.domain=self.optional('input/domain_knowledge.json',None)
            self.constraints=self.optional('input/generation_constraints.json',None)
        except (KeyError,ValueError,TypeError,IndexError,StopIteration) as exc:
            self.fail('Malformed parent run: '+type(exc).__name__)

    def fail(self,message):raise AgentError('PARENT_INTEGRITY_FAILED',message)
    def safe(self,path):
        path=Path(path)
        try:relative=path.relative_to(self.root)
        except ValueError:self.fail('Artifact escapes parent run')
        current=self.root
        for part in relative.parts:
            current=current/part
            if part=='..' or current.is_symlink():self.fail('Unsafe artifact path')
        if not path.resolve().is_relative_to(self.root):self.fail('Artifact escapes parent run')
        return path
    def path(self,value):
        value=str(value);p=pure_path(value)
        if '..' in p.parts:self.fail('Parent traversal in artifact reference')
        actual=Path(value)
        if actual.is_absolute() and actual.is_relative_to(self.root):return self.safe(actual)
        if p.is_absolute():
            try:p=p.relative_to(self.original)
            except ValueError:self.fail('Artifact outside original run')
        return self.safe(self.root.joinpath(*p.parts))
    def check(self,path,checksum):
        path=self.safe(path)
        if not path.is_file() or sha256_file(path)!=checksum:self.fail('Artifact hash mismatch: '+path.name)
        self.dependencies[path.relative_to(self.root).as_posix()]=checksum
    def text(self,value):
        path=self.path(value) if not isinstance(value,Path) else self.safe(value)
        if not path.is_file() or path.stat().st_size>64*1024*1024:self.fail('Missing/oversized artifact: '+path.name)
        text=path.read_text(encoding='utf-8');self.dependencies[path.relative_to(self.root).as_posix()]=sha256_file(path)
        return text
    def read(self,value):return strict_json(self.text(value))
    def optional(self,value,default):return self.read(value) if self.path(value).exists() else default
    def status(self):
        return {'integrity_status':'PASSED','verification_availability':
                {sid:{'P':r.get('precondition',{}).get('status','NOT_RUN'),
                      'contract':r.get('verification',{}).get('verdict','NOT_RUN')} for sid,r in self.verified.items()},
                'missing_context':self.missing,'analysis_origin':'REEXTRACTED_FROM_HASH_CHECKED_SNAPSHOTS',
                'source_and_spec_hashes':dict(self.dependencies)}
