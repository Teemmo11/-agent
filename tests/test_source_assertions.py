"""New-protocol orchestration/attribution regression; fixtures are not C proofs."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from helpers import ROOT,fake_tools
from spec_agent.adapters import cbmc,c2btor
from spec_agent.config import Config,load_config
from spec_agent.controller import run
from spec_agent.errors import AgentError
from spec_agent.preflight import doctor
from spec_agent.verification.audit import audit_run


MODEL='''; c2btor-property-contract selected-assertions-only
1 sort bitvec 1
2 state 1 x
3 zero 1
4 one 1
5 init 1 2 3
6 next 1 2 4
7 constraint 4
8 bad 2 first
9 bad 3 second
'''

def metadata(version='1'):
    rows=[]
    for pid,bad,cond,line in [('first',8,2,1),('second',9,3,2)]:
        rows.append(dict(property_id=pid,bad_node=bad,condition_node=cond,pure_condition_node=cond,
                         property_class='assertion',elimination_reason='',source=dict(file_name='program.c',line=str(line),function='main')))
    return dict(format_version=version,blocks=[] if version=='2' else None,source_properties=rows,
                property_selection=dict(merged=False,scope='all-goto-assertions',semantics='selected-assertions-only',lifetime_top='none'),
                memory=dict(frozen_on_violation=False,proof_obligations=[],properties=[]))


class SourceQueryTests(unittest.TestCase):
    def query(self,model=MODEL,data=None,target=9,pid='second'):
        with tempfile.TemporaryDirectory() as t:
            m=Path(t)/'model.btor2';p=Path(t)/'map.json';m.write_text(model);p.write_text(json.dumps(data or metadata()))
            return c2btor.queries(m,p,target,pid,profile=cbmc.SOURCE_PROFILE)

    def test_selection_preserves_all_dynamics_and_handles_v1_v2(self):
        for version in ('1','2'):
            source,boundary,obligations=self.query(data=metadata(version))
            self.assertEqual(source,MODEL.replace('8 bad 2 first\n',''))
            self.assertIsNone(boundary);self.assertEqual(obligations,[])

    def test_unreachable_source_must_be_false(self):
        data=metadata();data['source_properties'][1]['elimination_reason']='unreachable_after_constant_folding'
        self.query(data=data)
        data['source_properties'][0]['elimination_reason']='unreachable_after_constant_folding'
        with self.assertRaises(AgentError):self.query(data=data)

    def test_rejects_merged_undeclared_ambiguous_impure_and_old_memory(self):
        variations=[]
        d=metadata();d['property_selection']['merged']=True;variations.append(d)
        d=metadata();d['source_properties'].pop();variations.append(d)
        d=metadata();d['source_properties'][1]['property_id']='first';variations.append(d)
        d=metadata();d['source_properties'][1]['condition_node']=4;variations.append(d)
        d=metadata();d['source_properties'][1]['pure_condition_node']=4;variations.append(d)
        d=metadata();d['memory']['frozen_on_violation']=True;variations.append(d)
        d=metadata();d['memory']['proof_obligations']=[{}];variations.append(d)
        d=metadata();d['source_properties'][1]['source']['file_name']='';variations.append(d)
        d=metadata();d['format_version']='3';variations.append(d)
        for d in variations:
            with self.subTest(data=d),self.assertRaises(AgentError):self.query(data=d)

    def test_contract_profiles_cannot_be_crossed_and_arrays_are_blocked(self):
        with self.assertRaises(AgentError):self.query(model=MODEL.replace(c2btor.SOURCE_CONTRACT,c2btor.CONTRACT))
        with self.assertRaises(AgentError):self.query(model=MODEL+'10 sort array 1 1\n')

    def test_source_commands_disable_slicing_keep_bv_and_select_checks_only_for_static(self):
        caps={'cbmc_profile':cbmc.SOURCE_PROFILE,'cbmc_flags':cbmc.SOURCE_BUILD_FLAGS+cbmc.SAFETY_FLAGS}
        for kind in ('HOARE_POSTCONDITION','CBMC_STATIC_PROPERTY'):
            job=SimpleNamespace(kind=kind,source_files=['program.c'],entry='main',generation_flags=cbmc.SAFETY_FLAGS)
            argv=cbmc.build_command(job,'m.btor2','map.json',caps,'p')
            self.assertNotIn('--property',argv);self.assertNotIn('--function',argv)
            self.assertIn('--goto-btor2-no-slice-property',argv);self.assertIn('--goto-btor2-no-lbe',argv)
            self.assertEqual('--goto-btor2-checks' in argv,kind=='CBMC_STATIC_PROPERTY')
            self.assertEqual(argv[argv.index('--array')+1],'bv')
        job=SimpleNamespace(kind='CBMC_STATIC_PROPERTY',source_files=['program.c'],entry='helper',generation_flags=cbmc.SAFETY_FLAGS)
        with self.assertRaises(AgentError):cbmc.build_command(job,'m.btor2','map.json',caps,'p')


@unittest.skipIf(os.name=='nt','POSIX fixture executables require WSL/Linux')
class SourcePipelineTests(unittest.TestCase):
    def execute(self,t,scenario='source_holds',branch='hoare'):
        with patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin',scenario)}):
            return run([ROOT/('examples/array_bug/program.c' if branch=='static' else 'examples/clamp/program.c')],
                       ROOT/'examples/clamp/requirements.md',Config(tool_mode='MOCK'),output=Path(t)/'runs',branch=branch,
                       fixture=ROOT/'examples/clamp/llm_fixture.json' if branch=='hoare' else None,entry='main' if branch=='static' else None)

    def test_help_omissions_are_supported_by_actual_contract_probe_and_explicit_tool_selection(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin','source_holds')}):
            caps=doctor(Config(tool_mode='MOCK',cbmc_command='c2btor'),Path(t)/'doctor')
            self.assertTrue(caps['ready']);self.assertEqual(caps['cbmc_profile'],cbmc.SOURCE_PROFILE)
            self.assertNotIn('--property',caps['cbmc_flags']);self.assertEqual(caps['source_conversion_probe']['status'],'PASSED')
            self.assertEqual(Path(caps['tools']['cbmc']['executable']).name,'c2btor')

    def test_advertised_protocol_with_invalid_probe_fails_closed(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin','source_bad_probe')}):
            caps=doctor(Config(tool_mode='MOCK'),Path(t)/'doctor')
            self.assertFalse(caps['ready']);self.assertIn('SOURCE_CONTRACT_PROBE_FAILED',caps['issues'])

    def test_feasibility_and_clause_verdicts_and_no_boundary_queries(self):
        for scenario,expected,p in [('source_holds','HOLDS','FEASIBLE'),('source_violated','VIOLATED','FEASIBLE'),
                                    ('source_vacuous','VACUOUS','INFEASIBLE')]:
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as t:
                root,result=self.execute(t,scenario)
                self.assertEqual(result['contracts'][0]['verification']['verdict'],expected)
                self.assertEqual(result['contracts'][0]['precondition']['status'],p)
                self.assertEqual(audit_run(root,require_real=False)['status'],'PASSED')
                self.assertFalse(list(root.rglob('boundaries.btor2')))
                q=result['contracts'][0]['properties'][0]
                self.assertEqual(q['model_contract']['profile'],cbmc.SOURCE_PROFILE)
                self.assertNotIn('5 bad',Path(q['evidence_manifest']).with_name('model.btor2').read_text())
                self.assertIn('5 bad',Path(q['model_contract']['converter_model']).read_text())
                self.assertEqual(result['evaluation'],{'status':'NOT_RUN'})

    def test_static_discovery_uses_conversion_map_and_hash_binds_it(self):
        with tempfile.TemporaryDirectory() as t:
            root,result=self.execute(t,branch='static')
            self.assertEqual(result['status'],'COMPLETED');self.assertEqual(len(result['static_properties']),2)
            self.assertEqual(audit_run(root,require_real=False)['status'],'PASSED')
            self.assertEqual(result['static_properties'][0]['discovery_scope'],'CONVERSION_SOURCE_MAP')
            (root/'generation/cbmc/discovery_map.json').write_text('{}')
            self.assertEqual(audit_run(root,require_real=False)['status'],'FAILED')

    def test_audit_detects_query_and_conversion_flag_tampering(self):
        for tamper in ('model','argv','policy','moved'):
            with self.subTest(tamper=tamper),tempfile.TemporaryDirectory() as t:
                root,result=self.execute(t)
                q=result['contracts'][0]['properties'][0]
                if tamper=='model':
                    p=Path(q['evidence_manifest']).with_name('model.btor2');p.write_text(p.read_text().replace('2 zero','2 one'))
                elif tamper=='argv':
                    p=Path(q['execution_refs']['cbmc']);data=json.loads(p.read_text());data['argv'].remove('--goto-btor2-no-slice-property');p.write_text(json.dumps(data))
                elif tamper=='policy':
                    q['model_contract']['property_slicing']=True
                    disk=Path(q['evidence_manifest']).with_name('result.json');data=json.loads(disk.read_text());data['model_contract']['property_slicing']=True
                    disk.write_text(json.dumps(data));(root/'result.json').write_text(json.dumps(result))
                else:
                    moved=Path(t)/'moved';shutil.copytree(root,moved)
                    self.assertEqual(audit_run(moved,require_real=False)['status'],'PASSED');continue
                self.assertEqual(audit_run(root,require_real=False)['status'],'FAILED')

    def test_converter_name_configuration_rejects_commands(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'config.env';p.write_text('CBMC_COMMAND=c2btor\n')
            with patch.dict(os.environ,{},clear=True):self.assertEqual(load_config(p).cbmc_command,'c2btor')
            p.write_text('CBMC_COMMAND=cbmc --other\n')
            with patch.dict(os.environ,{},clear=True),self.assertRaises(AgentError):load_config(p)

    def test_unknown_or_timeout_cannot_publish_success(self):
        for scenario in ('source_unknown','source_timeout'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as t:
                with patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin',scenario)}):
                    root,result=run([ROOT/'examples/clamp/program.c'],ROOT/'examples/clamp/requirements.md',
                        Config(tool_mode='MOCK',tool_timeout=0.5 if scenario=='source_timeout' else 60),
                        output=Path(t)/'runs',branch='hoare',fixture=ROOT/'examples/clamp/llm_fixture.json')
                c=result['contracts'][0]
                self.assertNotIn(c['verification']['verdict'],('HOLDS','VIOLATED'))
                for p in [c['precondition']['result'],*c['properties']]:
                    self.assertFalse(p['conclusion_gate']['allowed'])
                    self.assertNotIn(p['verdict'],('HOLDS','VIOLATED'))
                self.assertEqual(audit_run(root,require_real=False)['status'],'FAILED')
