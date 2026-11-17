import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from helpers import ROOT
from scripts.real_validation import assess,canonical

class AcceptanceContractTests(unittest.TestCase):
    def test_comparison_canonical_equivalence(self):
        pairs=[('x < low','low > x'),('x <= low','low >= x'),
               ('x == low','low == x'),('x != low','low != x')]
        for left,right in pairs:
            with self.subTest(left=left,right=right):self.assertEqual(canonical(left),canonical(right))
        self.assertNotEqual(canonical('x < low'),canonical('x > low'))
    def test_assess_accepts_directionally_equivalent_clauses(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);sem=json.loads((ROOT/'examples/clamp/llm_fixture.json').read_text())['clamp']
            sem['function_spec']['post_conditions'][0]['formal_candidate']='low <= result'
            sem['function_spec']['post_conditions'][1]['formal_candidate']='high >= result'
            path=root/'spec.json';path.write_text(json.dumps(sem))
            c={'function':'clamp','verification':{'verdict':'HOLDS'},'precondition':{'status':'FEASIBLE'},
               'provenance':{'semantic_spec':str(path)},'properties':[{'property_id':'HS.Q1','verdict':'HOLDS'},{'property_id':'HS.Q2','verdict':'HOLDS'}]}
            self.assertEqual(assess('clamp',root,{'mode':'REAL','status':'COMPLETED','contracts':[c]}),[])
    def test_holds_verdict_does_not_bypass_expression_mismatch(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);sem=json.loads((ROOT/'examples/clamp/llm_fixture.json').read_text())['clamp']
            sem['function_spec']['post_conditions'][0]['formal_candidate']='result == low'
            path=root/'spec.json';path.write_text(json.dumps(sem))
            c={'function':'clamp','verification':{'verdict':'HOLDS'},'precondition':{'status':'FEASIBLE'},
               'provenance':{'semantic_spec':str(path)},'properties':[{'property_id':'HS.Q1','verdict':'HOLDS'},{'property_id':'HS.Q2','verdict':'HOLDS'}]}
            errors=assess('clamp',root,{'mode':'REAL','status':'COMPLETED','contracts':[c]})
            self.assertIn('Q1_BENCHMARK_MISMATCH',errors)
    def test_weak_or_changed_contract_never_passes(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);sem=json.loads((ROOT/'examples/clamp/llm_fixture.json').read_text())['clamp']
            path=root/'spec.json';path.write_text(json.dumps(sem))
            c={'function':'clamp','verification':{'verdict':'HOLDS'},'precondition':{'status':'FEASIBLE'},
               'provenance':{'semantic_spec':str(path)},'properties':[{'property_id':'HS.Q1','verdict':'HOLDS'},{'property_id':'HS.Q2','verdict':'HOLDS'}]}
            r={'mode':'REAL','status':'COMPLETED','contracts':[c]}
            self.assertEqual(assess('clamp',root,r),[])
            sem['function_spec']['pre_condition']['formal_candidate']='x == 0'
            path.write_text(json.dumps(sem))
            self.assertIn('PRECONDITION_BENCHMARK_MISMATCH',assess('clamp',root,r))
            sem['function_spec']['pre_condition']['formal_candidate']='low <= high'
            sem['function_spec']['post_conditions'][0]['guard']='0'
            path.write_text(json.dumps(sem))
            self.assertIn('Q1_BENCHMARK_MISMATCH',assess('clamp',root,r))
            sem['function_spec']['post_conditions'][0]['guard']='low <= high'
            path.write_text(json.dumps(sem))
            self.assertIn('Q1_BENCHMARK_MISMATCH',assess('clamp',root,r))
