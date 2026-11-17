import tempfile
import unittest

from evaluation_helpers import make_parent
from spec_agent.errors import AgentError
from spec_agent.evaluation.loader import ParentRun
from spec_agent.evaluation.strength import assess, plan_cases


class RecordedQueries:
    def __init__(self, *results):
        self.results = iter(results)
        self.calls = []

    def query(self, function, spec_id, kind, predicate):
        self.calls.append((kind, predicate))
        raw = next(self.results)
        return {'status': 'DECIDED' if raw else 'UNKNOWN', 'raw_result': raw,
                'query_id': f'query-{len(self.calls)}'}


class StrengthTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root, _ = make_parent(self.directory.name, pre='x >= 0', guard='x < 10')
        self.parent = ParentRun(root)
        self.suite = {'f': {
            'invalid_inputs': [{'id': 'negative', 'inputs': {'x': -1},
                                'requirement': 'REQ-1', 'reason': 'Outside input domain.'}],
            'invalid_outputs': [{'id': 'changed', 'inputs': {'x': 2}, 'result': 3,
                                 'requirement': 'REQ-1', 'reason': 'Output differs from x.'},
                                {'id': 'changed-2', 'inputs': {'x': 3}, 'result': 4,
                                 'requirement': 'REQ-1', 'reason': 'Output differs from x.'}],
        }}

    def test_counts_only_decided_cases_and_respects_guard(self):
        engine = RecordedQueries('SAT', 'SAT', 'UNSAT', None)
        result = assess(plan_cases(self.parent, self.suite, {}), engine)
        self.assertNotIn('__sa_result', engine.calls[1][1])
        post_query = engine.calls[2][1]
        for expected in ('x == 2LL', '__sa_result == 3LL', 'x >= 0', 'x < 10', '__sa_result == x'):
            self.assertIn(expected, post_query)
        self.assertEqual(result['metrics']['PreComp']['score'], 1)
        self.assertEqual(result['metrics']['PostComp']['score'], 0)
        self.assertEqual(result['metrics']['PostComp']['undecided'], 1)
        self.assertEqual(result['functions'][0]['cases'][-1]['query_id'], 'query-4')

    def test_infeasible_precondition_and_empty_metric_have_no_score(self):
        del self.suite['f']['invalid_outputs']
        engine = RecordedQueries('UNSAT')
        result = assess(plan_cases(self.parent, self.suite, {}), engine)
        self.assertEqual(len(engine.calls), 1)
        self.assertIsNone(result['metrics']['PreComp']['score'])
        self.assertEqual(result['functions'][0]['cases'][0]['reason_code'], 'P_INFEASIBLE')
        self.assertEqual(result['metrics']['PostComp']['status'], 'NO_CASES')
        self.assertIsNone(result['metrics']['PostComp']['score'])

    def test_rejects_out_of_range_and_duplicate_cases(self):
        case = self.suite['f']['invalid_inputs'][0]
        self.suite['f']['invalid_inputs'].append({**case, 'id': 'duplicate'})
        with self.assertRaisesRegex(AgentError, 'duplicates'):
            plan_cases(self.parent, self.suite, {})
        self.suite['f']['invalid_inputs'].pop()
        case['inputs']['x'] = -(1 << 31) - 1
        with self.assertRaisesRegex(AgentError, 'must be an integer'):
            plan_cases(self.parent, self.suite, {})

    def test_valid_inputs_use_p_and_distinguish_exclusion_from_unknown(self):
        valid_inputs = [
            {'id': f'valid-{x}', 'inputs': {'x': x}, 'requirement': 'REQ-1', 'reason': 'Valid input.'}
            for x in (1, 0, 2)
        ]
        engine = RecordedQueries('SAT', 'UNSAT', None)
        result = assess(plan_cases(self.parent, {'f': {'valid_inputs': valid_inputs}}, {}), engine)
        self.assertEqual([kind for kind, _ in engine.calls], ['PreCorr'] * 3)
        self.assertIn('x == 0LL', engine.calls[1][1])
        self.assertTrue(engine.calls[1][1].endswith('((x >= 0)))'))
        self.assertEqual(result['metrics']['PreCorr'], {
            'total': 3, 'decided': 2, 'retained': 1, 'excluded': 1, 'undecided': 1,
            'score': 0.5, 'status': 'PARTIAL',
        })
        self.assertEqual([case['outcome'] for case in result['functions'][0]['cases']],
                         ['RETAINED', 'EXCLUDED', 'UNDECIDED'])

    def test_rejects_conflicting_input_labels(self):
        case = self.suite['f']['invalid_inputs'][0]
        self.suite['f']['valid_inputs'] = [{**case, 'id': 'also-valid'}]
        with self.assertRaisesRegex(AgentError, 'both valid and outside'):
            plan_cases(self.parent, self.suite, {})
