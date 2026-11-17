"""Controller-owned benchmark constraints; MOCK orchestration, not live proofs."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from helpers import ROOT, fake_tools
from scripts.real_validation import DOMAIN, main as acceptance_main
from spec_agent.analysis.functions import CAnalyzer
from spec_agent.artifacts import sha256_file
from spec_agent.config import Config
from spec_agent.controller import run
from spec_agent.errors import AgentError
from spec_agent.llm.parser import SCHEMA, parse_response, response_schema
from spec_agent.llm.prompts import messages
from spec_agent.trace import read_events


class GenerationConstraintTests(unittest.TestCase):
    def setUp(self):
        self.program = CAnalyzer().analyze([ROOT / 'examples/clamp/buggy.c'])
        self.function = self.program.functions[0]
        self.data = json.loads((ROOT / 'examples/clamp/llm_fixture.json').read_text())['clamp']

    def parse(self, data, constrained=False):
        return parse_response(json.dumps(data), self.function, {'ids': ['REQ-001']},
                              self.program, require_unguarded_posts=constrained)

    def guard_schema(self, schema):
        return schema['properties']['function_spec']['properties']['post_conditions']['items']['properties']['guard']

    def test_benchmark_prompt_and_schema_require_json_null(self):
        prompt = messages(self.function, {'ids': ['REQ-001']}, DOMAIN, require_unguarded_posts=True)
        self.assertIn('every postcondition guard MUST be JSON null', prompt[0]['content'])
        self.assertIn('Do not use a string', prompt[0]['content'])
        context = json.loads(prompt[-1]['content'])
        self.assertEqual(context['generation_constraints'], {'postcondition_guard': 'NULL_ONLY'})
        self.assertEqual(self.guard_schema(context['output_schema']), {'type': 'null'})
        self.assertIn('guard set to JSON null for BOTH', DOMAIN)

    def test_constraint_schema_does_not_mutate_generic_schema(self):
        constrained = response_schema(require_unguarded_posts=True)
        self.guard_schema(constrained)['type'] = 'boolean'
        self.assertEqual(self.guard_schema(SCHEMA)['type'], ['string', 'null'])
        self.assertEqual(self.guard_schema(response_schema())['type'], ['string', 'null'])
        prompt = messages(self.function, {'ids': ['REQ-001']}, DOMAIN)
        context = json.loads(prompt[-1]['content'])
        self.assertNotIn('generation_constraints', context)
        self.assertEqual(self.guard_schema(context['output_schema'])['type'], ['string', 'null'])

    def test_null_guard_is_accepted_without_changing_precondition(self):
        result = self.parse(self.data, constrained=True)
        self.assertEqual(result, self.data)
        self.assertEqual(result['function_spec']['pre_condition']['formal_candidate'], 'low <= high')

    def test_non_null_guards_are_rejected_and_not_rewritten(self):
        for index in (0, 1):
            for guard in ('low <= high', 'x > 0', '0', '', 'null', False, 0):
                with self.subTest(index=index, guard=guard):
                    data = deepcopy(self.data)
                    data['function_spec']['post_conditions'][index]['guard'] = guard
                    with self.assertRaises(AgentError) as error:
                        self.parse(data, constrained=True)
                    self.assertEqual(error.exception.code, 'LLM_RESPONSE_INVALID')
                    self.assertIn(f'post_conditions[{index}].guard', str(error.exception))
                    self.assertEqual(data['function_spec']['post_conditions'][index]['guard'], guard)

    def test_generic_caller_guard_is_preserved(self):
        self.data['function_spec']['post_conditions'][0]['guard'] = 'x > 0'
        result = self.parse(self.data)
        self.assertEqual(result['function_spec']['post_conditions'][0]['guard'], 'x > 0')

    def pipeline(self, base, data, *, constrained=True, scenario='violated'):
        fixture = base / 'fixture.json'
        fixture.write_text(json.dumps({'clamp': data}))
        tool_path = fake_tools(base / 'bin', scenario)
        with patch.dict(os.environ, {'PATH': tool_path}):
            return run([ROOT / 'examples/clamp/buggy.c'], ROOT / 'examples/clamp/requirements.md',
                       Config(tool_mode='MOCK', tool_timeout=5), output=base / 'runs', fixture=fixture,
                       branch='hoare', domain=DOMAIN, require_unguarded_posts=constrained)

    def test_invalid_guard_stops_before_formalization_and_verification(self):
        self.data['function_spec']['post_conditions'][0]['guard'] = 'low <= high'
        with tempfile.TemporaryDirectory() as tmp:
            root, result = self.pipeline(Path(tmp), self.data)
            self.assertEqual(result['status'], 'COMPLETED_WITH_ERRORS')
            self.assertEqual(result['contracts'], [])
            self.assertEqual(result['generation']['llm_specs'], 0)
            self.assertEqual(result['failures'][0]['error']['code'], 'LLM_RESPONSE_INVALID')
            self.assertFalse((root / 'verification').exists())
            self.assertFalse((root / 'specs/formal').exists())
            directory = root / 'generation/llm/functions' / result['failures'][0]['function_id']
            raw = json.loads((directory / 'response.txt').read_text())
            self.assertEqual(raw['function_spec']['post_conditions'][0]['guard'], 'low <= high')
            self.assertTrue((directory / 'error.json').is_file())
            self.assertFalse((directory / 'spec.json').exists())
            events = list(read_events(root / 'events.jsonl'))
            rejected = next(e for e in events if e['event'] == 'llm.generation.failed')
            self.assertEqual(rejected['details']['stage'], 'parse_and_validate')
            self.assertNotIn('spec.accepted', [e['event'] for e in events])
            self.assertEqual(events[-1]['event'], 'run.finished')
            self.assertEqual(result['logging']['status'], 'COMPLETE')

    def test_valid_buggy_constraint_is_snapshotted_and_evidence_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, result = self.pipeline(Path(tmp), self.data)
            contract = result['contracts'][0]
            self.assertEqual(contract['precondition']['status'], 'FEASIBLE')
            self.assertEqual(contract['verification']['verdict'], 'VIOLATED')
            self.assertEqual([p['verdict'] for p in contract['properties']], ['HOLDS', 'VIOLATED'])
            constraints = root / 'input/generation_constraints.json'
            self.assertEqual(json.loads(constraints.read_text()), {'postcondition_guard': 'NULL_ONLY'})
            semantic = json.loads(Path(contract['provenance']['semantic_spec']).read_text())
            self.assertEqual(semantic['generation']['constraints'], {'postcondition_guard': 'NULL_ONLY'})
            for property in [contract['precondition']['result'], *contract['properties']]:
                bound = json.loads(Path(property['evidence_manifest']).read_text())
                self.assertEqual(bound[str(constraints)], sha256_file(constraints))

    def test_generic_pipeline_keeps_guard_in_harness(self):
        self.data['function_spec']['post_conditions'][0]['guard'] = 'x > 0'
        with tempfile.TemporaryDirectory() as tmp:
            root, result = self.pipeline(Path(tmp), self.data, constrained=False)
            self.assertEqual(result['status'], 'COMPLETED')
            self.assertFalse((root / 'input/generation_constraints.json').exists())
            q1 = next((root / 'verification').glob('*.Q1/harness.c')).read_text()
            self.assertIn('__sa_guard =', q1)
            self.assertIn('x > 0', q1)
            self.assertIn('!__sa_guard ||', q1)

    def test_infeasible_precondition_is_not_repaired(self):
        self.data['function_spec']['pre_condition']['formal_candidate'] = 'x > 0 && x < 0'
        with tempfile.TemporaryDirectory() as tmp:
            _, result = self.pipeline(Path(tmp), self.data, scenario='vacuous')
            contract = result['contracts'][0]
            self.assertEqual(contract['precondition']['status'], 'INFEASIBLE')
            self.assertEqual(contract['verification']['verdict'], 'VACUOUS')
            formal = json.loads(Path(contract['provenance']['formal_contract']).read_text())
            self.assertIn('x > 0', formal['precondition_expr'])
            self.assertIn('x < 0', formal['precondition_expr'])

    def test_acceptance_enables_constraint_only_for_hoare_cases(self):
        for case in ('clamp', 'buggy', 'infeasible', 'array'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                caps = {'ready': True, 'semantic_probe': {'status': 'PASSED'},
                        'llm': {'configured': case != 'array'}}
                with patch('scripts.real_validation.load_config', return_value=Config()), \
                     patch('scripts.real_validation.doctor', return_value=caps), \
                     patch('scripts.real_validation.run', return_value=(Path(tmp) / 'case', {})) as launch, \
                     patch('scripts.real_validation.audit_run', return_value={'status': 'PASSED'}), \
                     patch('scripts.real_validation.assess', return_value=[]), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(acceptance_main(['--case', case, '--output', tmp]), 0)
                self.assertEqual(launch.call_args.kwargs['require_unguarded_posts'], case != 'array')
                self.assertTrue(launch.call_args.kwargs['require_real'])

    def test_invalid_constraint_configuration_is_blocked_before_tool_access(self):
        for value, branch in (('true', 'hoare'), (1, 'hoare'), (None, 'hoare'), (True, 'static')):
            with self.subTest(value=value, branch=branch), tempfile.TemporaryDirectory() as tmp, \
                 patch('spec_agent.controller.doctor', side_effect=AssertionError('must not access tools')):
                _, result = run([ROOT / 'examples/clamp/program.c'], ROOT / 'examples/clamp/requirements.md',
                                Config(tool_mode='MOCK'), output=tmp, branch=branch,
                                require_unguarded_posts=value)
                self.assertEqual(result['status'], 'FAILED')
                self.assertEqual(result['failures'][0]['code'], 'CONFIG_INVALID')
