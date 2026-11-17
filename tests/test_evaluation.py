import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from spec_agent.artifacts import sha256_file,write_json_atomic
from spec_agent.config import Config
from spec_agent.errors import AgentError
from spec_agent.evaluation.controller import evaluate
from spec_agent.evaluation.loader import ParentRun
from spec_agent.evaluation.audit import audit_evaluation
from spec_agent.evaluation.models import Limits,Budget
from spec_agent.evaluation.context import ContextBuilder
from spec_agent.evaluation.requirements import index_requirements
from spec_agent.evaluation.semantic import parse_review,review_findings
from spec_agent.evaluation.deterministic import canonical
from spec_agent.evaluation.harness import render,expressions
from spec_agent.evaluation.aggregate import dimensions
from spec_agent.evaluation.logic import LogicEngine
from evaluation_helpers import make_parent,review_response


class EvaluationTests(unittest.TestCase):
    def test_offline_assessment_is_immutable_and_does_not_launch_tools_or_llm(self):
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p')
            before={p.relative_to(parent):sha256_file(p) for p in parent.rglob('*') if p.is_file()}
            with patch('spec_agent.evaluation.controller.doctor',side_effect=AssertionError('tool call')):
                root,r=evaluate(parent,Config(),output=Path(t)/'eval')
            self.assertEqual(r['execution_status'],'COMPLETED');self.assertEqual(r['budget']['llm_calls'],0)
            self.assertEqual(r['dimensions']['alignment']['status'],'NOT_RUN')
            self.assertEqual(audit_evaluation(root)['status'],'PASSED')
            self.assertEqual(before,{p.relative_to(parent):sha256_file(p) for p in parent.rglob('*') if p.is_file()})

    def test_schema_canonical_references_and_report_utf8(self):
        repo=Path(__file__).parents[1]
        for name in ('evaluation','evaluation_context','evaluation_finding'):
            schema=json.loads((repo/'schemas'/(name+'.schema.json')).read_text())
            self.assertTrue((repo/'schemas'/schema['$ref']).is_file())
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p',clauses=['result >= x','x <= result'])
            root,r=evaluate(parent,Config(),output=Path(t)/'eval')
            self.assertTrue(any(f['code']=='DUPLICATE_CLAUSE' for f in r['findings']))
            self.assertIn('规约评估报告',(root/'report.md').read_text(encoding='utf-8'))
            self.assertEqual(audit_evaluation(root)['status'],'PASSED')

    def test_parent_source_and_spec_tampering_blocks_assessment(self):
        for kind in ('source','spec','summary'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as t:
                parent,s=make_parent(Path(t)/'p')
                if kind=='source':next((parent/'input/source').rglob('*.c')).write_text('int f(int x){return 0;}')
                elif kind=='spec':
                    path=parent/'specs/semantic'/(s['spec_id']+'.json');value=json.loads(path.read_text());value['function_spec']['post_conditions'][0]['formal_candidate']='1';write_json_atomic(path,value)
                else:
                    path=parent/'result.json';value=json.loads(path.read_text());value['input']['requirements_sha256']='bad';write_json_atomic(path,value)
                root,r=evaluate(parent,Config(),output=Path(t)/'eval')
                self.assertEqual(r['execution_status'],'BLOCKED')
                self.assertEqual(audit_evaluation(root)['status'],'PASSED') # A correctly recorded blocked assessment.

    def test_parent_traversal_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p');p=ParentRun(parent)
            for value in ('../outside','input/../../outside','C:\\outside\\x'):
                with self.subTest(path=value),self.assertRaises(AgentError):p.path(value)
            try:(parent/'escape').symlink_to(Path(t),target_is_directory=True)
            except OSError:return
            with self.assertRaises(AgentError):p.path('escape/program.c')

    def test_context_cites_original_spans_but_blinds_implementation_and_verdict(self):
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p');_,context,builder=review_response(parent)
            view=builder.review_view(context);text=json.dumps(view)
            self.assertNotIn('return x;',text);self.assertNotIn('verification_snapshot',text)
            self.assertNotIn('HOLDS',text)
            for evidence in view['evidence_catalog'].values():
                self.assertTrue(evidence['sha256']);self.assertTrue(evidence['artifact_ref'])

    def test_review_cannot_invent_evidence_ids_or_clauses_or_duplicate_dimensions(self):
        for kind in ('reference','clause','dimension','proof'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as t:
                parent,_=make_parent(Path(t)/'p');value,context,builder=review_response(parent)
                if kind=='reference':value['dimensions'][0]['evidence_ids']=['FAKE']
                elif kind=='clause':value['coverage'][0]['clause_ids']=['Q999']
                elif kind=='dimension':value['dimensions'][0]['dimension']=value['dimensions'][1]['dimension']
                else:value['dimensions'][0]['claim_status']='PROVED'
                with self.assertRaises(AgentError):parse_review(json.dumps(value),context,set(builder.review_view(context)['evidence_catalog']))

    def test_fixture_reviews_are_judgments_and_do_not_upgrade_parent_mode(self):
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p');value,_,_=review_response(parent)
            fixture=Path(t)/'reviews.json';write_json_atomic(fixture,{value['spec_id']:value})
            root,r=evaluate(parent,Config(),output=Path(t)/'eval',reviewer='fixture',review_fixture=fixture)
            self.assertEqual(r['execution_status'],'COMPLETED');self.assertEqual(r['assessment_mode']['parent_mode'],'FIXTURE_LLM_REAL_TOOLS')
            self.assertEqual(r['reviews'][0]['assessment_mode'],'FIXTURE_REVIEW')
            self.assertEqual(audit_evaluation(root)['status'],'PASSED')
            _,blocked=evaluate(parent,Config(),output=Path(t)/'real',reviewer='fixture',review_fixture=fixture,require_real=True)
            self.assertEqual(blocked['execution_status'],'BLOCKED')

    def test_budget_exhaustion_and_large_context_are_not_successful_reviews(self):
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p');value,_,_=review_response(parent)
            fixture=Path(t)/'reviews.json';write_json_atomic(fixture,{value['spec_id']:value})
            root,r=evaluate(parent,Config(),output=Path(t)/'eval',reviewer='fixture',review_fixture=fixture,limits=Limits(llm_calls=0))
            self.assertEqual(r['execution_status'],'PARTIAL');self.assertFalse(r['reviews'])
            self.assertEqual(r['budget']['llm_calls'],0);self.assertEqual(audit_evaluation(root)['status'],'PASSED')
            parent2,_=make_parent(Path(t)/'big',requirements='REQ-1:\n'+('Long requirement. '*10000))
            root,r=evaluate(parent2,Config(),output=Path(t)/'large',reviewer='fixture',review_fixture=fixture,limits=Limits(input_tokens=512))
            self.assertEqual(r['execution_status'],'PARTIAL');self.assertEqual(r['budget']['llm_calls'],0)

    def test_moved_parent_and_evaluation_audit_and_tamper(self):
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p');root,_=evaluate(parent,Config(),output=Path(t)/'eval')
            moved=Path(t)/'moved-parent';shutil.copytree(parent,moved)
            moved_eval=Path(t)/'moved-eval';shutil.copytree(root,moved_eval)
            self.assertEqual(audit_evaluation(moved_eval,parent_root=moved)['status'],'PASSED')
            value=json.loads((moved_eval/'evaluation.json').read_text(encoding='utf-8'));value['stop_reason']='tampered';write_json_atomic(moved_eval/'evaluation.json',value)
            self.assertEqual(audit_evaluation(moved_eval,parent_root=moved)['status'],'FAILED')

    def test_requirement_inventory_preserves_uncited_requirements(self):
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p',requirements='REQ-1:\nReturn x.\nREQ-2:\nAnother requirement.\n')
            _,r=evaluate(parent,Config(),output=Path(t)/'eval')
            missing=[row for row in r['coverage']['rows'] if row['requirement_id']=='REQ-2'][0]
            self.assertEqual(missing['coverage_status'],'MISSING')
            self.assertTrue(any(f['code']=='REQUIREMENT_UNREFERENCED' for f in r['findings']))

    def test_query_harness_is_typed_and_has_no_implementation_call(self):
        with tempfile.TemporaryDirectory() as t:
            parent,s=make_parent(Path(t)/'p',source='unsigned int f(unsigned int x) { return x; }\n',clauses=['result >= old(x)'])
            p=ParentRun(parent);f=next(iter(p.functions.values()));pre,clauses=expressions(s,f)
            text,line=render(f,'('+pre+') && !('+clauses[0]['q']+')','EQ-example')
            self.assertIn('unsigned int __sa_result',text);self.assertIn('unsigned int __sa_old_x = x',text)
            self.assertNotIn('f(',text);self.assertIn('__CPROVER_assert(0',text.splitlines()[line-1])
            self.assertEqual(canonical('result >= x',f),canonical('x <= result',f))

    def test_unknown_parent_does_not_require_a_successful_proof_audit(self):
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p');path=parent/'result.json';r=json.loads(path.read_text())
            r['contracts'][0]['precondition']['status']='UNKNOWN';r['contracts'][0]['verification']['verdict']='UNKNOWN';write_json_atomic(path,r)
            root,result=evaluate(parent,Config(),output=Path(t)/'eval')
            self.assertEqual(result['execution_status'],'COMPLETED');self.assertEqual(audit_evaluation(root)['status'],'PASSED')
            self.assertEqual(next(iter(result['verification_snapshot'].values()))['P'],'UNKNOWN')

    def test_dimension_statuses_do_not_claim_unexecuted_checks(self):
        result=dimensions([],[],logic='tools',uncertain=[],reference_checked=True,
                          queries=[{'kind':'P_FEASIBILITY'}])
        self.assertEqual(result['strength']['status'],'NO_ISSUE_FOUND')
        self.assertEqual(result['consistency']['status'],'NOT_RUN')
        result=dimensions([],[],logic='tools',uncertain=[{'reason':'TIMEOUT'}],queries=[])
        self.assertEqual(result['nontriviality']['status'],'UNKNOWN')
        self.assertEqual(result['strength']['status'],'NOT_RUN')

    def test_cached_unknown_queries_remain_unknown_for_each_consumer(self):
        with tempfile.TemporaryDirectory() as t:
            parent,spec=make_parent(Path(t)/'p');p=ParentRun(parent)
            engine=LogicEngine(Path(t)/'queries',{},Config(),Budget(),None,{})
            def cached_query(function,sid,kind,predicate,clauses=()):
                # Evidence cached from a different specification; no solver call.
                decided=kind in ('P_FEASIBILITY','GUARD_ACTIVE')
                return {'query_id':'EQ-cached','spec_id':'OTHER','raw_result':'SAT' if decided else None,
                        'status':'DECIDED' if decided else 'UNKNOWN','evidence_id':'EV-EQ-cached'}
            with patch.object(engine,'query',side_effect=cached_query):
                findings,missing=engine.evaluate(spec,p.functions[spec['function_id']],[])
            self.assertFalse(findings);self.assertTrue(missing)
            self.assertTrue(all(r['reason']=='UNKNOWN' for r in missing))

    def test_review_report_is_bound_to_its_raw_response(self):
        from spec_agent.evaluation.controller import seal
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p');value,_,_=review_response(parent)
            fixture=Path(t)/'review.json';write_json_atomic(fixture,{value['spec_id']:value})
            root,_=evaluate(parent,Config(),output=Path(t)/'eval',reviewer='fixture',review_fixture=fixture)
            raw=next((root/'semantic').glob('*/*/response.txt'));changed=json.loads(raw.read_text(encoding='utf-8'))
            changed['needs_clarification']=True;write_json_atomic(raw,changed);seal(root)
            audit=audit_evaluation(root)
            self.assertEqual(audit['status'],'FAILED');self.assertIn('REVIEW_RESPONSE_MISMATCH',audit['errors'])

    def test_attribution_resolves_original_paths_before_host_path_operations(self):
        from types import SimpleNamespace
        from spec_agent.evaluation.audit import resolve_query_mapping
        from spec_agent.evaluation.loader import pure_path
        for base in ('/original/evaluation','C:\\original\\evaluation'):
            with self.subTest(root=base):
                source=str(pure_path(base)/'queries'/'EQ-test'/'harness.c')
                job=SimpleNamespace(harness_file=source,assertion_line=7,entry='__sa_entry')
                row={'property_id':'P','bad_node':9,'kind':'ASSERT','property_class':'assertion',
                     'source':{'file_name':source,'line':'7','function':'__sa_entry'}}
                resolve=lambda ref:Path('/relocated').joinpath(*pure_path(ref).relative_to(pure_path(base)).parts)
                self.assertEqual(resolve_query_mapping({'instructions':[row]},job,'P',[9],base,resolve),9)
                row['source']['line']='8'
                with self.assertRaises(AgentError):resolve_query_mapping({'instructions':[row]},job,'P',[9],base,resolve)

    def test_missing_specs_and_recursive_or_unresolved_calls_remain_partial(self):
        sources={'missing':'int f(int x) { return x; } int g(int y) { return y; }\n',
                 'recursive':'int f(int x) { if(x) return f(x); return 0; }\n',
                 'unresolved':'int f(int x) { return external_call(x); }\n'}
        for case,source in sources.items():
            with self.subTest(case=case),tempfile.TemporaryDirectory() as t:
                parent,_=make_parent(Path(t)/'p',source=source)
                root,result=evaluate(parent,Config(),output=Path(t)/'eval')
                self.assertEqual(result['execution_status'],'PARTIAL')
                self.assertEqual(audit_evaluation(root)['status'],'PASSED')
                if case=='missing':self.assertTrue(result['coverage']['functions_without_specs'])

    def test_boolean_query_values_are_canonicalized_without_changing_predicate(self):
        from spec_agent.evaluation.logic import query_key
        with tempfile.TemporaryDirectory() as t:
            parent,s=make_parent(Path(t)/'p',source='_Bool f(_Bool x) { return x; }\n',clauses=['result == x'])
            p=ParentRun(parent);f=p.functions[s['function_id']]
            text,_=render(f,'(__sa_result != x)','EQ-boolean')
            self.assertIn('_Bool x = (__CPROVER_nondet_input_0() != 0);',text)
            self.assertIn('_Bool __sa_result = (__CPROVER_nondet_output() != 0);',text)
            self.assertIn('__CPROVER_assume((__sa_result != x));',text)
            self.assertEqual(text.count('__CPROVER_assume'),1)
            identity,_=query_key(f,'(__sa_result != x)',{})
            self.assertIn('bool_value_normalization',identity['symbol_domain'])

    def test_utf8_reference_and_review_fixture_ignore_host_default_encoding(self):
        with tempfile.TemporaryDirectory() as t:
            parent,spec=make_parent(Path(t)/'p');value,_,_=review_response(parent)
            value['dimensions'][0]['explanation']='中文规约评审：返回值必须等于输入。📌'
            fixture=Path(t)/'review.json';write_json_atomic(fixture,{value['spec_id']:value})
            reference=Path(t)/'reference.json'
            target={'function_spec':spec['function_spec'],'callee_expectations':[]}
            target['function_spec']['expected_behavior']='返回输入，不新增假设。📌'
            write_json_atomic(reference,target)
            original_read=Path.read_text
            def host_read(path,*args,**kwargs):
                if not args and kwargs.get('encoding') is None:kwargs['encoding']='cp936'
                return original_read(path,*args,**kwargs)
            with patch.object(Path,'read_text',host_read):
                root,result=evaluate(parent,Config(),output=Path(t)/'eval',reviewer='fixture',
                                     review_fixture=fixture,reference_spec=reference)
                audit=audit_evaluation(root)
            self.assertEqual(result['execution_status'],'COMPLETED')
            self.assertEqual(result['reviews'][0]['dimensions'][0]['explanation'],value['dimensions'][0]['explanation'])
            self.assertEqual(audit['status'],'PASSED')
