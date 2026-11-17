import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from spec_agent.artifacts import write_json_atomic,sha256_file
from spec_agent.config import Config
from spec_agent.evaluation.controller import evaluate
from spec_agent.evaluation.loader import ParentRun
from spec_agent.evaluation.models import Limits
from spec_agent.refinement.controller import refine
from spec_agent.refinement.policy import SeenCandidates,scope_check,decide,semantic_delta,quality_delta
from spec_agent.refinement.audit import audit_refinement
from evaluation_helpers import make_parent


def proposal(spec,**updates):
    candidate={'function_spec':copy.deepcopy(spec['function_spec']),'callee_expectations':copy.deepcopy(spec['callee_expectations'])}
    for key,value in updates.items():
        if key=='pre':candidate['function_spec']['pre_condition']['formal_candidate']=value
        elif key=='guard':candidate['function_spec']['post_conditions'][0]['guard']=value
        elif key=='q':candidate['function_spec']['post_conditions'][0]['formal_candidate']=value
    return {'candidate':candidate,'needs_clarification':False,
            'changes':[{'clause_id':'Q1','explanation':'Fixture requirement-based proposal.','evidence_ids':['$REQ:0']}]}


class RefinementPolicyTests(unittest.TestCase):
    def test_scope_freezes_preconditions_guards_and_obligations(self):
        with tempfile.TemporaryDirectory() as t:
            parent,spec=make_parent(Path(t)/'p',clauses=['result == x','result >= x']);p=ParentRun(parent)
            for changes,reason in [({'pre':'x == 0'},'PRECONDITION_CHANGED'),({'guard':'x == 0'},'GUARD_CHANGED:Q1')]:
                with self.subTest(changes=changes):self.assertIn(reason,scope_check(spec,proposal(spec,**changes)['candidate'],p))
            candidate=proposal(spec)['candidate'];candidate['function_spec']['post_conditions'].pop()
            self.assertIn('OBLIGATION_REMOVED',scope_check(spec,candidate,p))

    def test_cycle_detection_includes_the_original_candidate(self):
        with tempfile.TemporaryDirectory() as t:
            _,spec=make_parent(Path(t)/'p');seen=SeenCandidates(spec)
            a=proposal(spec)['candidate'];b=proposal(spec,q='result >= x')['candidate']
            self.assertTrue(seen.add(b)[0]);self.assertFalse(seen.add(a)[0]);self.assertFalse(seen.add(b)[0])

    def test_program_violation_does_not_reject_an_improved_specification(self):
        before={'findings':[{'spec_id':'S','severity':'HIGH','dimension':'strength','code':'WEAK','clause_ids':['Q1']}]}
        after={'execution_status':'COMPLETED','reviews':[],'findings':[]}
        self.assertEqual(decide(before,after,'S','VIOLATED',has_reference=True)[0],'ACCEPTED')
        self.assertEqual(decide(before,after,'S','UNKNOWN',has_reference=True)[0],'INCONCLUSIVE')
        self.assertEqual(decide(before,after,'S','HOLDS',has_reference=False)[0],'NEEDS_REVIEW')

    def test_semantic_issues_cannot_disappear_by_disabling_or_changing_reviewer(self):
        before={'findings':[{'spec_id':'S','severity':'HIGH','dimension':'alignment','code':'MISALIGNED',
                             'clause_ids':['Q1'],'evidence_kind':'LLM_JUDGMENT'}],
                'reviews':[{'spec_id':'S','reviewer_identity':{'model':'reviewer-a'}}]}
        after={'execution_status':'COMPLETED','reviews':[],'findings':[]}
        self.assertEqual(decide(before,after,'S','HOLDS',has_reference=True),
                         ('NEEDS_REVIEW','PREVIOUS_SEMANTIC_CHECK_NOT_REPEATED'))
        after['reviews']=[{'spec_id':'S','needs_clarification':False,'reviewer_identity':{'model':'reviewer-b'}}]
        self.assertEqual(decide(before,after,'S','HOLDS',has_reference=True),
                         ('NEEDS_REVIEW','REVIEWER_IDENTITY_CHANGED'))
        after['reviews'][0]['reviewer_identity']={'model':'reviewer-a'}
        self.assertEqual(decide(before,after,'S','VIOLATED',has_reference=True)[0],'ACCEPTED')

    def test_version_deltas_survive_json_and_keep_old_new_obligations(self):
        with tempfile.TemporaryDirectory() as t:
            _,spec=make_parent(Path(t)/'p');change=semantic_delta(spec,proposal(spec,q='result >= x')['candidate'])
            self.assertEqual(change['clauses'][0]['before']['formal_candidate'],'result == x')
            self.assertEqual(change['clauses'][0]['after']['formal_candidate'],'result >= x')
            before={'findings':[{'spec_id':'S','severity':'HIGH','dimension':'strength','code':'WEAK','clause_ids':['Q1']}],'coverage':{'rows':[]}}
            after={'findings':[],'coverage':{'rows':[]}};quality=quality_delta(before,after,'S')
            self.assertEqual(json.loads(json.dumps(quality)),quality)
            self.assertEqual(quality['resolved_issues'],[['strength','WEAK',['Q1']]])

    def test_repeated_candidate_stops_before_model_calls(self):
        with tempfile.TemporaryDirectory() as t:
            parent,spec=make_parent(Path(t)/'p',clauses=['result >= x','x <= result'])
            # Supply a HIGH issue through the lack of a reference on a clause.
            spec['function_spec']['post_conditions'][0]['requirement_refs']=[]
            write_json_atomic(parent/'specs/semantic'/(spec['spec_id']+'.json'),spec)
            (parent/'generation/llm/functions'/spec['function_id']/'response.txt').write_text(json.dumps(
                {'function_spec':spec['function_spec'],'callee_expectations':[]}),encoding='utf-8')
            ev,before=evaluate(parent,Config(),output=Path(t)/'eval')
            fixture=Path(t)/'candidate.json';write_json_atomic(fixture,{'f':[proposal(spec)]})
            with patch('spec_agent.refinement.controller.verify_given_candidates',side_effect=AssertionError('model call')):
                root,result=refine(ev,Config(),output=Path(t)/'ref',proposer='fixture',candidate_fixture=fixture)
            self.assertEqual(result['stop_reason'],'DUPLICATE_CANDIDATE')
            self.assertEqual(result['decision'],'REJECTED');self.assertEqual(audit_refinement(root)['status'],'PASSED')

    def test_precondition_change_needs_review_without_starting_tools(self):
        with tempfile.TemporaryDirectory() as t:
            parent,spec=make_parent(Path(t)/'p',clauses=['1']);spec['function_spec']['ambiguities']=['needs review']
            # A deterministic target using a missing clause requirement reference.
            spec['function_spec']['ambiguities']=[];spec['function_spec']['post_conditions'][0]['requirement_refs']=[]
            write_json_atomic(parent/'specs/semantic'/(spec['spec_id']+'.json'),spec)
            (parent/'generation/llm/functions'/spec['function_id']/'response.txt').write_text(json.dumps({'function_spec':spec['function_spec'],'callee_expectations':[]}),encoding='utf-8')
            ev,_=evaluate(parent,Config(),output=Path(t)/'eval')
            fixture=Path(t)/'candidate.json';write_json_atomic(fixture,{'f':[proposal(spec,pre='x == 0')]})
            with patch('spec_agent.refinement.controller.verify_given_candidates',side_effect=AssertionError('model call')):
                root,result=refine(ev,Config(),output=Path(t)/'ref',proposer='fixture',candidate_fixture=fixture)
            self.assertEqual(result['decision'],'NEEDS_REVIEW');self.assertEqual(result['stop_reason'],'PROTECTED_SCOPE_CHANGED')
            self.assertIn('PRECONDITION_CHANGED',result['iterations'][0]['scope_changes'])
            self.assertEqual(audit_refinement(root)['status'],'PASSED')

    def test_global_budget_and_iteration_limit_stop_before_any_llm_call(self):
        for limit in ('iterations','calls'):
            with self.subTest(limit=limit),tempfile.TemporaryDirectory() as t:
                parent,spec=make_parent(Path(t)/'p');spec['function_spec']['post_conditions'][0]['requirement_refs']=[]
                write_json_atomic(parent/'specs/semantic'/(spec['spec_id']+'.json'),spec)
                (parent/'generation/llm/functions'/spec['function_id']/'response.txt').write_text(json.dumps({'function_spec':spec['function_spec'],'callee_expectations':[]}),encoding='utf-8')
                ev,_=evaluate(parent,Config(),output=Path(t)/'eval');fixture=Path(t)/'candidate.json';write_json_atomic(fixture,{'f':[proposal(spec,q='result >= x')]})
                root,result=refine(ev,Config(),output=Path(t)/'ref',proposer='fixture',candidate_fixture=fixture,
                    max_iterations=0 if limit=='iterations' else 2,limits=Limits(llm_calls=0 if limit=='calls' else 10))
                self.assertEqual(result['execution_status'],'PARTIAL');self.assertEqual(result['budget']['llm_calls'],0)
                self.assertEqual(result['stop_reason'],'ITERATION_LIMIT' if limit=='iterations' else 'REFINEMENT_BUDGET_EXHAUSTED')
                self.assertEqual(audit_refinement(root)['status'],'PASSED')

    def test_refinement_report_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p');ev,_=evaluate(parent,Config(),output=Path(t)/'eval')
            fixture=Path(t)/'candidate.json';write_json_atomic(fixture,{'f':[]})
            root,_=refine(ev,Config(),output=Path(t)/'ref',proposer='fixture',candidate_fixture=fixture)
            report=json.loads((root/'refinement.json').read_text(encoding='utf-8'));report['source_program_changed']=True
            write_json_atomic(root/'refinement.json',report);self.assertEqual(audit_refinement(root)['status'],'FAILED')

    def test_output_cannot_mutate_the_immutable_parent(self):
        from spec_agent.errors import AgentError
        with tempfile.TemporaryDirectory() as t:
            parent,_=make_parent(Path(t)/'p');ev,_=evaluate(parent,Config(),output=Path(t)/'eval')
            before={p.relative_to(parent):sha256_file(p) for p in parent.rglob('*') if p.is_file()}
            with self.assertRaises(AgentError):refine(ev,Config(),output=parent/'refinements')
            self.assertFalse((parent/'refinements').exists())
            self.assertEqual(before,{p.relative_to(parent):sha256_file(p) for p in parent.rglob('*') if p.is_file()})
