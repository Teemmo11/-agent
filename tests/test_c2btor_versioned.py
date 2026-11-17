"""Versioned converter policy, target semantics and fail-closed integration."""
import json
import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from helpers import ROOT,fake_tools
from test_source_assertions import metadata,MODEL
from spec_agent.adapters import cbmc,c2btor
from spec_agent.config import Config,load_config
from spec_agent.controller import run
from spec_agent.errors import AgentError
from spec_agent.preflight import doctor
from spec_agent.verification.audit import audit_run
from spec_agent.evaluation.logic import query_key
from spec_agent.models import FunctionContext


def caps(model='LP64'):
    return {'cbmc_profile':cbmc.SOURCE_PROFILE,'cbmc_source_schema':cbmc.SOURCE_SCHEMA,
            'cbmc_target_model':model,'cbmc_flags':cbmc.SOURCE_BUILD_FLAGS+cbmc.SOURCE_SCHEMA_FLAGS+cbmc.SAFETY_FLAGS}


def source_map(model='LP64'):
    data=metadata();policy=cbmc.source_policy(caps(model))
    data.update(schema_version='c2btor-source-map-1',int_width=32,long_long_width=64,
                long_width=32 if model=='ILP32' else 64,pointer_width=32 if model=='ILP32' else 64,
                optimization_config={k:v for k,v in policy.items() if k not in ('schema_version','data_model')})
    return data


class VersionedPolicyTests(unittest.TestCase):
    def test_actual_model_configuration_and_widths_must_match(self):
        for model in ('LP64','ILP32'):
            c2btor.validate_source_policy(source_map(model),caps(model))
        for change in ('schema','missing-config','malformed-config','unknown-config','merge','slice','state','lbe','array','target','summary','heap'):
            with self.subTest(change=change):
                data=source_map()
                if change=='schema':data['schema_version']='future'
                elif change=='missing-config':data.pop('optimization_config')
                elif change=='malformed-config':data['optimization_config']=[]
                elif change=='unknown-config':data['optimization_config']['unreviewed_pass']=True
                elif change=='target':data['long_width']=32
                elif change=='array':data['optimization_config']['array']='array'
                else:
                    key={'merge':'merge_bads','slice':'property_slicing','state':'optimize_state','lbe':'lbe',
                         'summary':'scalar_loop_summary','heap':'symbolic_heap_bv_array_fallback'}[change]
                    data['optimization_config'][key]=True
                with self.assertRaises(AgentError):c2btor.validate_source_policy(data,caps())

    def test_unknown_map_schema_is_rejected_without_relaxing_old_maps(self):
        with tempfile.TemporaryDirectory() as t:
            m=Path(t)/'m';p=Path(t)/'map';m.write_text(MODEL)
            p.write_text(json.dumps(metadata()));c2btor.source_inventory(m,p)
            data=metadata();data['schema_version']='c2btor-source-map-999';p.write_text(json.dumps(data))
            with self.assertRaises(AgentError):c2btor.source_inventory(m,p)

    def test_command_and_quality_cache_bind_target_and_policy(self):
        function=FunctionContext('f','f','','long',[],'',0,0,'','')
        identities=[]
        for model,flag in [('LP64','--64'),('ILP32','--32')]:
            argv=cbmc.source_command(['input.c'],'main',[],'m','map',caps(model))
            for value in (flag,'--goto-btor2-no-merge-bads','--goto-btor2-no-optimize-state',
                          '--goto-btor2-no-scalar-blocks','--goto-btor2-no-lbe','--goto-btor2-no-slice-property'):
                self.assertIn(value,argv)
            self.assertNotIn('--property',argv);self.assertNotIn('--goto-btor2-merge-bads',argv)
            identities.append(query_key(function,'1',caps(model))[1])
        self.assertNotEqual(*identities)
        self.assertNotEqual(cbmc.execution_identity(caps('LP64')),cbmc.execution_identity(caps('ILP32')))

    def test_configuration_rejects_unspecified_data_models(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{},clear=True):
            p=Path(t)/'config';p.write_text('C2BTOR_DATA_MODEL=ILP32\n')
            self.assertEqual(load_config(p).c2btor_data_model,'ILP32')
            p.write_text('C2BTOR_DATA_MODEL=native\n')
            with self.assertRaises(AgentError):load_config(p)


@unittest.skipIf(os.name=='nt','POSIX fixture executables require WSL/Linux')
class VersionedPipelineTests(unittest.TestCase):
    def test_protocol_probe_checks_numeric_flags_and_ignored_policy(self):
        for scenario,ready in [('source_versioned_holds',True),('source_versioned_ignored_policy',False)]:
            with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin',scenario)}):
                report=doctor(Config(tool_mode='MOCK',cbmc_command='c2btor',c2btor_data_model='ILP32'),Path(t)/'preflight')
                self.assertEqual(report['ready'],ready)
                self.assertEqual(report['cbmc_source_schema'],'c2btor-source-map-1')
                self.assertEqual(report['converter_policy']['data_model'],'ILP32')
                if not ready:self.assertIn('SOURCE_CONTRACT_PROBE_FAILED',report['issues'])

    def test_hoare_and_static_evidence_and_policy_tamper(self):
        for branch in ('hoare','static'):
            with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin','source_versioned_holds')}):
                root,result=run([ROOT/('examples/clamp/program.c' if branch=='hoare' else 'examples/array_bug/program.c')],
                    ROOT/'examples/clamp/requirements.md',Config(tool_mode='MOCK',cbmc_command='c2btor'),
                    output=Path(t)/'runs',branch=branch,fixture=ROOT/'examples/clamp/llm_fixture.json' if branch=='hoare' else None)
                self.assertEqual(result['status'],'COMPLETED')
                self.assertEqual(audit_run(root,require_real=False)['status'],'PASSED')
                q=result['contracts'][0]['properties'][0] if branch=='hoare' else result['static_properties'][0]
                self.assertEqual(q['model_contract']['converter_policy']['data_model'],'LP64')
                jobdir=Path(q['evidence_manifest']).parent
                record=json.loads((jobdir/'source_map.json').read_text())
                record['optimization_config']['merge_bads']=True
                (jobdir/'source_map.json').write_text(json.dumps(record))
                self.assertEqual(audit_run(root,require_real=False)['status'],'FAILED')

    def test_refinement_data_model_drift_requires_review_before_trial(self):
        from evaluation_helpers import make_parent
        from spec_agent.artifacts import write_json_atomic
        from spec_agent.evaluation.controller import evaluate
        from spec_agent.evaluation.controller import seal
        from spec_agent.refinement.controller import refine
        from spec_agent.refinement.audit import audit_refinement
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'PATH':fake_tools(Path(t)/'bin','source_versioned_holds')}):
            parent,spec=make_parent(Path(t)/'parent')
            spec['function_spec']['post_conditions'][0]['requirement_refs']=[]
            write_json_atomic(parent/'specs/semantic'/(spec['spec_id']+'.json'),spec)
            (parent/'generation/llm/functions'/spec['function_id']/'response.txt').write_text(json.dumps(
                {'function_spec':spec['function_spec'],'callee_expectations':[]}),encoding='utf-8')
            baseline,_=evaluate(parent,Config(tool_mode='MOCK',cbmc_command='c2btor',c2btor_data_model='ILP32'),
                                output=Path(t)/'evaluations')
            # A completed offline baseline has no invented logical decisions.
            # Bind an explicitly mock preflight identity to exercise drift.
            before_caps=doctor(Config(tool_mode='MOCK',cbmc_command='c2btor',c2btor_data_model='ILP32'),baseline/'preflight')
            write_json_atomic(baseline/'toolchain_manifest.json',before_caps);seal(baseline)
            candidate={'function_spec':copy.deepcopy(spec['function_spec']),'callee_expectations':[]}
            candidate['function_spec']['post_conditions'][0]['requirement_refs']=['REQ-1']
            proposal={'candidate':candidate,'needs_clarification':False,
                      'changes':[{'clause_id':'Q1','explanation':'Restore the missing citation.','evidence_ids':['$REQ:0']}]}
            fixture=Path(t)/'proposal.json';write_json_atomic(fixture,{'f':[proposal]})
            root,result=refine(baseline,Config(tool_mode='MOCK',cbmc_command='c2btor',c2btor_data_model='LP64'),
                               output=Path(t)/'refinements',proposer='fixture',candidate_fixture=fixture)
            self.assertEqual(result['decision'],'NEEDS_REVIEW')
            self.assertEqual(result['stop_reason'],'TOOLCHAIN_IDENTITY_CHANGED')
            self.assertFalse(result['iterations'][0]['trial_run'])
            self.assertEqual(audit_refinement(root)['status'],'PASSED')
