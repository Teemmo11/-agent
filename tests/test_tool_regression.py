import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch
from scripts.tool_regression import CASES, inspect_result, main
from spec_agent.config import Config


class ToolRegressionTests(unittest.TestCase):
    def fixture_result(self):
        return {'status': 'COMPLETED', 'mode': 'FIXTURE_LLM_REAL_TOOLS',
                'contracts': [{'precondition': {'status': 'FEASIBLE'},
                               'verification': {'verdict': 'HOLDS'}, 'properties': [{'verdict': 'HOLDS'}]}]}

    def test_successful_fixture_result_remains_non_live(self):
        item = inspect_result(CASES[0], self.fixture_result(), {'status': 'PASSED'})
        self.assertEqual(item['status'], 'PASSED')
        self.assertEqual(item['mode'], 'FIXTURE_LLM_REAL_TOOLS')

    def test_errors_unknown_mock_and_failed_audit_cannot_pass(self):
        for mode, verdict, audit in [('MOCK_ALL', 'HOLDS', 'PASSED'),
                                      ('FIXTURE_LLM_REAL_TOOLS', 'ERROR', 'PASSED'),
                                      ('FIXTURE_LLM_REAL_TOOLS', 'UNKNOWN', 'PASSED'),
                                      ('FIXTURE_LLM_REAL_TOOLS', 'HOLDS', 'FAILED')]:
            with self.subTest(mode=mode, verdict=verdict, audit=audit):
                result = self.fixture_result()
                result['mode'] = mode
                result['contracts'][0]['verification']['verdict'] = verdict
                self.assertEqual(inspect_result(CASES[0], result, {'status': audit})['status'], 'FAILED')

    def test_static_case_requires_an_attributed_bounds_violation(self):
        result = {'mode': 'REAL', 'status': 'COMPLETED', 'static_properties': [
            {'cbmc_property_id': 'main.array_bounds.2', 'category': 'array bounds', 'verdict': 'VIOLATED'}]}
        self.assertEqual(inspect_result(CASES[-1], result, {'status': 'PASSED'})['status'], 'PASSED')
        result['static_properties'][0]['verdict'] = 'HOLDS'
        self.assertEqual(inspect_result(CASES[-1], result, {'status': 'PASSED'})['status'], 'FAILED')

    def test_missing_tools_block_before_generation(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch('scripts.tool_regression.load_config', return_value=Config()), \
             patch('scripts.tool_regression.doctor', return_value={
                 'ready': False, 'semantic_probe': {'status': 'BLOCKED'}, 'issues': ['RIC3_MISSING']}), \
             patch('scripts.tool_regression.run') as launch, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--output', tmp]), 2)
            launch.assert_not_called()
