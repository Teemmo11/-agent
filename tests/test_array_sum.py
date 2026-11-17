"""Array/loop example and fixed benchmark checks; no simulated proof claims."""
import contextlib
import io
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from helpers import ROOT
from scripts.real_validation import DEFAULT_CASES, SUM_DOMAIN, assess, main
from spec_agent.analysis.functions import CAnalyzer
from spec_agent.config import Config
from spec_agent.llm.parser import parse_response
from spec_agent.spec.formalizer import formalize
from spec_agent.spec.harness import emit_harness


class ArraySumTests(unittest.TestCase):
    def setUp(self):
        self.source = ROOT / 'examples/array_sum/program.c'
        self.program = CAnalyzer().analyze([self.source])
        self.function = self.program.functions[0]
        self.spec = json.loads((ROOT / 'examples/array_sum/llm_fixture.json').read_text())['sum_array']

    def test_local_array_and_loop_with_scalar_return_are_supported(self):
        self.assertEqual(len(self.program.functions), 1)
        self.assertEqual(self.function.signature, 'int sum_array(void)')
        self.assertEqual(self.function.parameters, [])
        self.assertEqual(self.function.harness_issues, [])
        parsed = parse_response(json.dumps(self.spec), self.function, {'ids': ['REQ-001']},
                                self.program, require_unguarded_posts=True)
        self.assertEqual(parsed, self.spec)

    def test_harness_checks_true_precondition_separately_then_calls_loop_function(self):
        self.spec['spec_id'] = 'HS-SUM'
        contract = formalize(self.spec, self.function,
                             {'source_sha256': 'source', 'requirements_sha256': 'requirements'})
        self.assertEqual(contract.precondition_expr, '1')
        self.assertEqual(contract.required_snapshots, [])
        self.assertIsNone(contract.ensures[0].guard_expr)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            p = emit_harness(self.function, contract, None, [self.source], base / 'p')
            q = emit_harness(self.function, contract, contract.ensures[0], [self.source], base / 'q')
            probe = Path(p.harness_file).read_text()
            post = Path(q.harness_file).read_text()
            self.assertIn('__CPROVER_assume(1);', probe)
            self.assertIn('__CPROVER_assert(0,', probe)
            self.assertNotIn('sum_array();', probe)
            self.assertIn('int __sa_result = sum_array();', post)
            self.assertIn('__sa_result == 45', post)
            self.assertNotIn('__sa_guard', post)
            self.assertNotIn('__CPROVER_nondet_', post)

    def check_benchmark(self, spec=None, *, mode='REAL', p='FEASIBLE', verdict='HOLDS', properties=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            semantic = root / 'spec.json'
            semantic.write_text(json.dumps(spec or self.spec))
            contract = {'function': 'sum_array', 'verification': {'verdict': verdict},
                        'precondition': {'status': p}, 'provenance': {'semantic_spec': str(semantic)},
                        'properties': properties if properties is not None else [{'property_id': 'HS-SUM.Q1', 'verdict': 'HOLDS'}]}
            return assess('sum', root, {'mode': mode, 'status': 'COMPLETED', 'contracts': [contract]})

    def test_benchmark_accepts_expected_sum_and_equivalent_equality(self):
        self.assertEqual(self.check_benchmark(), [])
        self.spec['function_spec']['post_conditions'][0]['formal_candidate'] = '45 == result'
        self.assertEqual(self.check_benchmark(), [])

    def test_benchmark_rejects_changed_spec_guard_and_duplicate_clause(self):
        for field, value, expected in (
            ('formal_candidate', 'result == 36', 'Q1_BENCHMARK_MISMATCH'),
            ('formal_candidate', 'result >= 0', 'Q1_BENCHMARK_MISMATCH'),
            ('guard', '1', 'Q1_BENCHMARK_MISMATCH'),
            ('guard', '0', 'Q1_BENCHMARK_MISMATCH'),
        ):
            with self.subTest(field=field, value=value):
                changed = deepcopy(self.spec)
                changed['function_spec']['post_conditions'][0][field] = value
                self.assertIn(expected, self.check_benchmark(changed))
        self.spec['function_spec']['pre_condition']['formal_candidate'] = '0'
        self.assertIn('PRECONDITION_BENCHMARK_MISMATCH', self.check_benchmark())
        self.spec['function_spec']['pre_condition']['formal_candidate'] = '1'
        self.spec['function_spec']['post_conditions'] *= 2
        self.assertIn('CLAUSE_IDS_BENCHMARK_MISMATCH', self.check_benchmark())

    def test_non_real_unknown_and_vacuous_results_never_pass_benchmark(self):
        self.assertIn('NON_REAL_RUN', self.check_benchmark(mode='FIXTURE_LLM_REAL_TOOLS'))
        self.assertIn('UNEXPECTED_FEASIBILITY', self.check_benchmark(p='INFEASIBLE', verdict='VACUOUS'))
        self.assertIn('UNEXPECTED_CONTRACT_VERDICT', self.check_benchmark(verdict='UNKNOWN'))
        self.assertIn('UNEXPECTED_CLAUSE_VERDICTS', self.check_benchmark(properties=[{'property_id': 'HS-SUM.Q1', 'verdict': 'UNKNOWN'}]))

    def test_live_sum_entry_uses_own_domain_and_strict_generation_policy(self):
        self.assertEqual(DEFAULT_CASES, ('clamp', 'buggy', 'infeasible', 'array'))
        with tempfile.TemporaryDirectory() as tmp:
            caps = {'ready': True, 'semantic_probe': {'status': 'PASSED'}, 'llm': {'configured': True}}
            with patch('scripts.real_validation.load_config', return_value=Config()), \
                 patch('scripts.real_validation.doctor', return_value=caps), \
                 patch('scripts.real_validation.run', return_value=(Path(tmp) / 'case', {})) as launch, \
                 patch('scripts.real_validation.audit_run', return_value={'status': 'PASSED'}), \
                 patch('scripts.real_validation.assess', return_value=[]), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['--case', 'sum', '--output', tmp]), 0)
            self.assertEqual(launch.call_args.args[0], [self.source])
            self.assertEqual(launch.call_args.kwargs['domain'], SUM_DOMAIN)
            self.assertTrue(launch.call_args.kwargs['require_real'])
            self.assertTrue(launch.call_args.kwargs['require_unguarded_posts'])
            self.assertNotIn('fixture', launch.call_args.kwargs)
