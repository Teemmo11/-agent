"""Release gates and artifact binding for staged contracts."""
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from spec_agent.artifacts import sha256_file, write_json_atomic
from spec_agent.config import Config
from spec_agent.errors import AgentError
from spec_agent.ir_ab.semantics import Invalid
from spec_agent.t3t4 import graph
from spec_agent.t3t4.audit import audit
from spec_agent.t3t4.checks import Checks
from spec_agent.t3t4.cli import DEFAULT_LIBRARY
from spec_agent.t3t4.controller import run
from spec_agent.t3t4.input import freeze, read_json
from spec_agent.t3t4.trace import lookup

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples/t3t4'
LIB = Path(os.environ.get('IR_AB_LIBZ3', DEFAULT_LIBRARY))


class GraphTests(unittest.TestCase):
    def setUp(self):
        source = EXAMPLES / 'station_admission'
        self.frozen = freeze(read_json(source.with_suffix('.json')), source.with_suffix('.txt').read_bytes())

    def test_structure_scope_and_source_mutations(self):
        good = graph.empty(self.frozen)
        for op in graph.operations(self.frozen):
            good = graph.apply(good, op, self.frozen)
        check = graph.inspect(good, self.frozen)
        self.assertFalse(check['pending'])
        self.assertFalse(check['issues'])
        self.assertEqual(check['organization']['guards']['emergency'], 4)
        for fault in ('root', 'cycle', 'duplicate'):
            with self.subTest(fault=fault):
                broken = deepcopy(good)
                head = broken['roots'][0]
                if fault == 'root':
                    broken['roots'].pop(0)
                elif fault == 'cycle':
                    broken['nodes'][head]['members'].append(head)
                else:
                    broken['roots'].append(head)
                with self.assertRaises(Invalid):
                    graph.inspect(broken, self.frozen)
        leaf = graph.node_id('S1', '/args/0', 'clause')
        parent = graph.node_id('S1', '', 'group')
        for fault in ('leaf', 'guard', 'origin', 'role', 'p'):
            with self.subTest(fault=fault):
                broken = deepcopy(good)
                node = broken['nodes'][leaf]
                if fault == 'leaf':
                    del broken['nodes'][leaf]
                    broken['nodes'][parent]['members'].remove(leaf)
                elif fault == 'guard':
                    node['guard'] = None
                elif fault == 'origin':
                    node['origin']['s_version'] = '0'*64
                elif fault == 'role':
                    node.update(role='requires', expr=True, guard=None)
                    with self.assertRaises(Invalid):
                        graph.inspect(broken, self.frozen)
                    continue
                else:
                    broken['nodes'][graph.node_id('S0', '/args/0', 'clause')]['expr'] = True
                observed = graph.inspect(broken, self.frozen)
                self.assertTrue(observed['issues'] or observed['pending'])


@unittest.skipUnless(LIB.is_file(), 'real Z3 shared library required')
class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.temp_root = Path(self.temp.name)
        self.source = EXAMPLES / 'payment_route'
        self.fixture = EXAMPLES / 'payment_route.fixture.json'

    def execute(self, *, package=None, material=None, **options):
        return run(package or self.source.with_suffix('.json'),
                   material or self.source.with_suffix('.txt'),
                   library=LIB, output=self.temp_root / 'runs', **options)

    def test_success_trace_and_version_tamper(self):
        root, result = self.execute(fixture=self.fixture, mode='shadow', query_limit=9)
        self.assertTrue(result['publication_eligible'])
        self.assertEqual(result['auxiliary']['status'], 'PASS')
        self.assertEqual(result['auxiliary']['online'], 'NOT_RUN')
        self.assertTrue(audit(root)['publication_eligible'])
        index = read_json(root / 'trace/index.json')
        self.assertTrue(lookup(index, requirement='R1')['details']['S1']['output'])
        obligation = lookup(index, item=index['obligations']['S1']['checks'][0])
        self.assertIn('R1', obligation['requirements'])
        for file in ('inputs/original.txt', 'inputs/S-R.json', 't3/main/graph.json', 'evidence/0001/result.json'):
            target = root / file
            old = target.read_bytes()
            target.write_bytes(old + b'\n')
            self.assertIn('HASH_MISMATCH:' + file, audit(root)['errors'])
            target.write_bytes(old)
        next_root, second = self.execute(split=False)
        self.assertNotEqual(root, next_root)
        self.assertTrue(second['publication_eligible'])
        self.assertTrue(audit(root)['publication_eligible'])

    def test_draft_and_rejected_graph_remain_blocked(self):
        draft, result = self.execute(max_steps=2)
        self.assertEqual(result['main']['completeness'], 'DRAFT')
        self.assertEqual(read_json(draft/'t3/steps/0002/step.json')['check']['status'], 'PASS')
        self.assertFalse((draft / 't4/contract.c').exists())

        def remove_root(step, snapshot):
            if step == 2:
                snapshot['roots'].pop()
            return snapshot

        root, result = self.execute(fixture=self.fixture, inject=remove_root)
        self.assertEqual(result['main']['stop'], 'STEP_REJECTED')
        self.assertEqual(result['auxiliary']['status'], 'PASS')
        self.assertEqual(result['decision'], 'KEEP_MAIN_BLOCKED')
        self.assertEqual(result['t4']['status'], 'NOT_RUN')
        self.assertEqual(audit(root)['integrity'], 'PASS')

    def test_model_invalid_cached_mismatch_and_timeout_are_separate(self):
        invalid = self.temp_root / 'invalid.json'
        invalid.write_text('{"schema": false}', encoding='utf-8')
        _, result = self.execute(fixture=invalid, mode='shadow')
        self.assertTrue(result['publication_eligible'])
        self.assertEqual(result['auxiliary']['status'], 'FAIL')
        root, _ = self.execute(fixture=self.fixture, mode='shadow')
        _, reused = self.execute(cached=root/'auxiliary/candidate_binding.json', mode='shadow', split=False)
        self.assertEqual(reused['auxiliary']['status'], 'PASS')
        material = self.temp_root/'material.txt'
        material.write_bytes(self.source.with_suffix('.txt').read_bytes()+b'\n')
        _, changed = self.execute(cached=root/'auxiliary/candidate_binding.json', mode='shadow', material=material)
        self.assertTrue(changed['publication_eligible'])
        self.assertEqual(changed['auxiliary']['reason'], 'CANDIDATE_INPUT_MISMATCH')

        class Timeout:
            def __init__(self, _):
                pass

            def complete(self, *_args, **_kwargs):
                raise AgentError('LLM_TIMEOUT', 'test only')

        _, timed = self.execute(mode='shadow', config=Config('http://localhost:1', 'test', 'test-key'),
                                auxiliary_client=Timeout)
        self.assertEqual(timed['auxiliary']['reason'], 'LLM_TIMEOUT')
        self.assertEqual(timed['t4']['status'], 'PASS')

    def test_infeasible_unavailable_and_query_exhaustion(self):
        path = self.temp_root / 'input.json'
        package = read_json(self.source.with_suffix('.json'))
        package['S'][0]['expr'] = False
        write_json_atomic(path, package)
        _, result = self.execute(package=path)
        self.assertEqual(result['p_feasibility']['classification'], 'INFEASIBLE')
        self.assertEqual(result['main']['stop'], 'INPUT_P_INFEASIBLE')
        result = self.execute(query_limit=0)[1]
        self.assertEqual(result['p_feasibility']['check']['reason'], 'QUERY_BUDGET')
        self.assertFalse(result['publication_eligible'])
        root, result = run(self.source.with_suffix('.json'), self.source.with_suffix('.txt'),
                           output=self.temp_root, library=self.temp_root/'missing.so')
        self.assertEqual(result['p_feasibility']['check']['raw_result'], 'ERROR')
        self.assertEqual(audit(root)['integrity'], 'PASS')
        with patch('spec_agent.t3t4.checks.Solver.run_raw', return_value=('unknown\n', [])):
            _, result = self.execute()
        self.assertEqual(result['p_feasibility']['check']['raw_result'], 'UNKNOWN')
        self.assertEqual(result['main']['status'], 'UNKNOWN')
        self.assertEqual(result['t4']['status'], 'NOT_RUN')

    def test_missing_original_blocks_even_when_formulas_match(self):
        root, result = run(self.source.with_suffix('.json'), None, output=self.temp_root, library=LIB)
        self.assertEqual(result['main']['semantics'], 'PASS')
        self.assertEqual(result['main']['source'], 'FAIL')
        self.assertFalse(result['publication_eligible'])
        self.assertIn('SOURCE_ANCHOR_UNAVAILABLE', lookup(read_json(root/'trace/index.json'), requirement='R1')['gaps'])

    def test_actual_output_mutations(self):
        for fault in ('delete', 'boundary', 'frame', 'map'):
            with self.subTest(fault=fault):
                def edit(root):
                    path, mapping_path = root/'t4/contract.c', root/'t4/source_map.json'
                    lines = path.read_text(encoding='utf-8').splitlines()
                    if fault == 'delete':
                        lines.pop(next(i for i, line in enumerate(lines) if '>= 10' in line))
                    elif fault == 'boundary':
                        lines = [line.replace('<= 14', '<= 13') for line in lines]
                    elif fault == 'frame':
                        lines[1] = '  assigns lock;'
                    path.write_text('\n'.join(lines)+'\n', encoding='utf-8')
                    mapping = read_json(mapping_path)
                    mapping['output_sha256'] = sha256_file(path)
                    if fault == 'map':
                        next(iter(mapping['clauses'].values()))['line'] = 1
                    write_json_atomic(mapping_path, mapping)

                _, result = self.execute(output_inject=edit)
                self.assertEqual(result['main']['status'], 'PASS')
                self.assertEqual(result['t4']['status'], 'FAIL')
                self.assertFalse(result['publication_eligible'])
                if fault in ('delete', 'boundary'):
                    self.assertEqual(result['t4']['queries'][1]['raw_result'], 'SAT')
                    self.assertEqual(result['t4']['queries'][1]['witness_status'], 'REPLAYED')

    def test_conflict_blocks_t4_and_is_fault_injection(self):
        class Conflict(Checks):
            def ask(self, label, predicate, expected, dependencies):
                # Inject a different actual SMT query only for the orchestration control.
                return super().ask(label, True if label == 'diagnostics/Q' else predicate, expected, dependencies)

        root, result = self.execute(fixture=self.fixture, mode='shadow', checks_factory=Conflict)
        self.assertEqual(result['main']['status'], 'PASS')
        self.assertEqual(result['auxiliary']['status'], 'PASS')
        self.assertTrue(result['fault_injection'])
        self.assertEqual(result['decision'], 'CHECK_CHAIN_CONFLICT')
        self.assertEqual(result['t4']['status'], 'NOT_RUN')
        self.assertFalse((root/'t4/contract.c').exists())
