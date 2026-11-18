import copy
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spec_agent.artifacts import sha256_file, write_json_atomic
from spec_agent.config import Config
from spec_agent.controller import run
from spec_agent.errors import AgentError
from spec_agent.evaluation.loader import ParentRun
from spec_agent.evaluation.models import Limits
from spec_agent.phase2.controller import followup
from spec_agent.phase2.diagnosis import diagnose, route
from spec_agent.phase2.repair import apply
from helpers import ROOT, fake_tools


class RoutingTests(unittest.TestCase):
    def test_agent_rejects_invalid_loop_settings_before_first_phase(self):
        from spec_agent.cli import main
        with patch('spec_agent.cli.load_config', return_value=Config()), \
             patch('spec_agent.cli.run', side_effect=AssertionError('invalid configuration launched first phase')), \
             contextlib.redirect_stdout(io.StringIO()):
            status = main(['agent', '--source', str(ROOT/'examples/clamp/program.c'),
                           '--requirements', str(ROOT/'examples/clamp/requirements.md'),
                           '--strength-cases', str(ROOT/'examples/clamp/strength_cases.json'),
                           '--max-iterations', '11'])
        self.assertEqual(status, 2)

    def test_completed_violation_and_vacuity_do_not_enter_quality_evaluation(self):
        report = {'status': 'COMPLETED', 'contracts': [{'precondition': {'status': 'FEASIBLE'},
                  'verification': {'verdict': 'VIOLATED'},
                  'properties': [{'verdict': 'VIOLATED', 'conclusion_gate': {'allowed': True}}]}]}
        self.assertEqual(route(report), 'REPAIR_SOURCE')
        report['contracts'][0]['precondition']['status'] = 'INFEASIBLE'
        self.assertEqual(route(report), 'PRECONDITION_REVIEW_REQUIRED')
        report['contracts'][0].update(precondition={'status': 'FEASIBLE'}, verification={'verdict': 'HOLDS'},
                                     properties=[{'verdict': 'HOLDS', 'conclusion_gate': {'allowed': True}}])
        self.assertEqual(route(report), 'EVALUATE')
        report['failures'] = [{'code': 'GENERATION_FAILED'}]
        self.assertEqual(route(report), 'RETRY_OR_REVIEW')

    def test_cancelled_generate_only_and_unchecked_properties_stay_blocked(self):
        self.assertEqual(route({'status': 'CANCELLED'}), 'CANCELLED')
        self.assertEqual(route({'status': 'COMPLETED', 'phase': '1.1'}), 'NEEDS_VERIFICATION')
        self.assertNotEqual(route({'status': 'COMPLETED', 'static_properties': [
            {'verdict': 'HOLDS', 'conclusion_gate': {'allowed': False}}]}), 'EVALUATE')


@unittest.skipIf(os.name == 'nt', 'Tool orchestration requires POSIX/WSL')
class SubagentTests(unittest.TestCase):
    def make_run(self, directory, scenario='source_violated', source='buggy.c'):
        tools = fake_tools(directory/'bin', scenario)
        for executable in (directory/'bin').iterdir():
            text = executable.read_text()
            text = text.replace("and label.endswith('.Q2'):",
                "and label.endswith('.Q2') and not Path("+repr(str(directory/'repaired-switch'))+").exists():")
            executable.write_text(text)
        with patch.dict(os.environ, {'PATH': tools}):
            root, result = run([ROOT/'examples/clamp'/source], ROOT/'examples/clamp/requirements.md',
                               Config(tool_mode='MOCK'), output=directory/'runs', branch='hoare',
                               fixture=ROOT/'examples/clamp/llm_fixture.json')
        return root, result, tools

    def mapped_parent(self, directory):
        root, result, tools = self.make_run(directory)
        parent = ParentRun(root)
        prop = result['contracts'][0]['properties'][1]
        jobdir = parent.path(prop['evidence_manifest']).parent
        mapping = jobdir/'source_map.json'
        data = json.loads(mapping.read_text())
        data.setdefault('instructions', []).append({'kind': 'ASSIGN', 'pc': 31,
            'source': {'file_name': str(parent.source_paths[0]), 'function': 'clamp', 'line': '6'}})
        write_json_atomic(mapping, data)
        hashes = json.loads((jobdir/'evidence_hashes.json').read_text())
        hashes[str(mapping)] = sha256_file(mapping)
        write_json_atomic(jobdir/'evidence_hashes.json', hashes)
        parent = ParentRun(root)
        diagnosis = diagnose(parent)
        self.assertEqual(diagnosis['findings'][0]['map_status'], 'ATTRIBUTED')
        eid = diagnosis['locations'][0]['evidence_id']
        proposal = {'needs_review': False, 'explanation': 'Restore the required inclusive upper bound.',
                    'edits': [{'evidence_id': eid, 'old': 'return high + 1;', 'new': 'return high;'}]}
        return parent, diagnosis, proposal, tools

    def test_mapping_repair_cannot_change_parent_or_signature_or_inject_assumptions(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            parent, diagnosis, proposal, _ = self.mapped_parent(base)
            before = {p: sha256_file(p) for p in parent.root.rglob('*') if p.is_file()}
            paths, _ = apply(parent, diagnosis, proposal, base/'candidate')
            self.assertIn('return high;', paths[0].read_text())
            self.assertIn('return high + 1;', parent.source_paths[0].read_text())
            self.assertEqual(before, {p: sha256_file(p) for p in parent.root.rglob('*') if p.is_file()})
            for old, new, evidence in [('return high + 1;', '__CPROVER_assume(0); return high;', 'MAP-1'),
                                       ('int clamp', 'long clamp', 'MAP-1'),
                                       ('return high + 1;', 'return high;', 'NOT_ISSUED')]:
                invalid = copy.deepcopy(proposal)
                invalid['edits'][0] = {'evidence_id': evidence, 'old': old, 'new': new}
                with self.assertRaises(AgentError):
                    apply(parent, diagnosis, invalid, base/'invalid')

    def test_repair_then_reverify_frozen_pq_then_evaluate_in_one_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            parent, _, proposal, _ = self.mapped_parent(base)
            fixture = base/'repair.json'
            write_json_atomic(fixture, [proposal])
            before = {p: sha256_file(p) for p in parent.root.rglob('*') if p.is_file()}
            tools = str(base/'bin')+os.pathsep+os.environ.get('PATH', '')
            (base/'repaired-switch').touch()
            evaluation = {'execution_status': 'COMPLETED', 'stop_reason': 'STRENGTH_CASES_FINISHED',
                          'strength': {'metrics': {name: {'score': 1.0} for name in ('PreCorr', 'PreComp', 'PostComp')}}}
            with patch.dict(os.environ, {'PATH': tools}), \
                 patch('spec_agent.phase2.controller.evaluate_strength', return_value=(base/'evaluation', evaluation)) as evaluate:
                root, result = followup(parent.root, Config(tool_mode='MOCK'), ROOT/'examples/clamp/strength_cases.json',
                                        output=base/'child', repair_fixture=fixture)
            self.assertEqual(result['execution_status'], 'COMPLETED', result)
            self.assertEqual(result['stop_reason'], 'QUALITY_EVALUATED')
            self.assertEqual(len(result['iterations']), 1)
            evaluate.assert_called_once()
            final = ParentRun(result['final_run'])
            self.assertEqual(final.specs[0]['function_spec'], parent.specs[0]['function_spec'])
            self.assertEqual(final.report['contracts'][0]['verification']['verdict'], 'HOLDS')
            self.assertNotEqual(final.info['source_sha256'], parent.info['source_sha256'])
            self.assertEqual(final.report['evaluation'], {'status': 'NOT_RUN'})
            self.assertTrue((root/'iterations/001/diagnosis.json').is_file())
            self.assertEqual(before, {p: sha256_file(p) for p in parent.root.rglob('*') if p.is_file()})
            self.assertEqual(result['budget']['llm_calls'], 1)
            self.assertGreaterEqual(result['budget']['queries'], 6)

    def test_success_evaluates_without_model_and_iteration_limit_preserves_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            parent, _, _ = self.make_run(base, 'source_holds', 'program.c')
            evaluation = {'execution_status': 'PARTIAL', 'stop_reason': 'STRENGTH_CASES_UNDECIDED'}
            with patch('spec_agent.phase2.controller.evaluate_strength', return_value=(base/'eval', evaluation)), \
                 patch('spec_agent.phase2.controller.propose', side_effect=AssertionError('repair called')):
                _, result = followup(parent, Config(tool_mode='MOCK'), ROOT/'examples/clamp/strength_cases.json', output=base/'child')
            self.assertEqual(result['execution_status'], 'PARTIAL')
            self.assertEqual(result['iterations'], [])
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            parent, _, _, _ = self.mapped_parent(base)
            with patch('spec_agent.phase2.controller.propose', side_effect=AssertionError('budget bypass')):
                _, result = followup(parent.root, Config(tool_mode='MOCK'), ROOT/'examples/clamp/strength_cases.json',
                                     output=base/'child', max_iterations=0)
            self.assertEqual(result['stop_reason'], 'REPAIR_ITERATION_LIMIT')
            self.assertEqual(ParentRun(result['final_run']).report['contracts'][0]['verification']['verdict'], 'VIOLATED')

    def test_unknown_and_tool_crash_retry_once_without_requesting_source_patch(self):
        for scenario in ('source_unknown', 'crash'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                parent, _, tools = self.make_run(base, scenario)
                with patch.dict(os.environ, {'PATH': tools}), \
                     patch('spec_agent.phase2.controller.propose', side_effect=AssertionError('source edit for tool error')):
                    _, result = followup(parent, Config(tool_mode='MOCK'), ROOT/'examples/clamp/strength_cases.json',
                                         output=base/'child', max_iterations=3)
                self.assertEqual(result['stop_reason'], 'UNRECOVERED_PIPELINE_ERROR', result)
                self.assertEqual(len([row for row in result['iterations'] if row['trial_run']]), 1)
                self.assertEqual(result['budget']['llm_calls'], 0)

    def test_iteration_budget_no_labels_and_real_only_gates(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            parent, _, _, _ = self.mapped_parent(base)
            with patch('spec_agent.phase2.controller.propose', side_effect=AssertionError('budget bypass')):
                _, result = followup(parent.root, Config(tool_mode='MOCK'), ROOT/'examples/clamp/strength_cases.json',
                                     output=base/'child', limits=Limits(queries=0))
            self.assertEqual(result['execution_status'], 'PARTIAL')
            bad = base/'labels.json'
            write_json_atomic(bad, {'clamp': {'valid_inputs': []}})
            _, result = followup(parent.root, Config(tool_mode='MOCK'), bad, output=base/'bad-labels')
            self.assertEqual(result['execution_status'], 'ERROR')
            with self.assertRaises(AgentError):
                followup(parent.root, Config(), ROOT/'examples/clamp/strength_cases.json',
                         output=parent.root/'child')
            with self.assertRaises(AgentError):
                followup(parent.root, Config(), ROOT/'examples/clamp/strength_cases.json',
                         output=base/'real', require_real=True, repair_fixture='fixture.json')

    def test_shared_query_budget_blocks_a_reverification_before_any_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            parent, _, proposal, tools = self.mapped_parent(base)
            fixture = base/'repair.json'
            write_json_atomic(fixture, [proposal])
            with patch.dict(os.environ, {'PATH': tools}):
                _, result = followup(parent.root, Config(tool_mode='MOCK'), ROOT/'examples/clamp/strength_cases.json',
                                     output=base/'child', repair_fixture=fixture, limits=Limits(queries=3))
            self.assertEqual(result['stop_reason'], 'REPAIR_BUDGET_EXHAUSTED', result)
            self.assertEqual(result['evaluation'], None)

    def test_agent_shares_budget_with_the_initial_verification(self):
        from spec_agent.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            tools = fake_tools(base/'bin', 'source_holds')
            with patch.dict(os.environ, {'PATH': tools}), \
                 patch('spec_agent.cli.load_config', return_value=Config(tool_mode='MOCK')), \
                 contextlib.redirect_stdout(io.StringIO()):
                status = main(['agent', '--source', str(ROOT/'examples/clamp/program.c'),
                    '--requirements', str(ROOT/'examples/clamp/requirements.md'), '--branch', 'hoare',
                    '--llm-fixture', str(ROOT/'examples/clamp/llm_fixture.json'),
                    '--strength-cases', str(ROOT/'examples/clamp/strength_cases.json'),
                    '--max-queries', '0', '--output', str(base/'runs')])
            self.assertEqual(status, 3)
            children = list((base/'runs').rglob('subagent.json'))
            self.assertEqual(len(children), 1)
            child = json.loads(children[0].read_text())
            self.assertEqual(child['stop_reason'], 'REPAIR_BUDGET_EXHAUSTED')
            self.assertEqual(child['budget']['queries'], 0)
            self.assertFalse(list((base/'runs').rglob('harness.c')))

    def test_tool_identity_drift_and_missing_original_source_map_block_acceptance(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            parent, _, proposal, _ = self.mapped_parent(base)
            fixture = base/'repair.json'
            write_json_atomic(fixture, [proposal])
            changed_tools = fake_tools(base/'changed-bin', 'source_holds')
            with patch.dict(os.environ, {'PATH': changed_tools}), \
                 patch('spec_agent.phase2.controller.evaluate_strength', side_effect=AssertionError('drift accepted')):
                _, result = followup(parent.root, Config(tool_mode='MOCK'), ROOT/'examples/clamp/strength_cases.json',
                                     output=base/'child', repair_fixture=fixture)
            self.assertEqual(result['stop_reason'], 'TOOLCHAIN_IDENTITY_CHANGED')
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            parent, _, _ = self.make_run(base)
            with patch('spec_agent.phase2.controller.propose', side_effect=AssertionError('unmapped repair')):
                _, result = followup(parent, Config(tool_mode='MOCK'), ROOT/'examples/clamp/strength_cases.json',
                                     output=base/'child')
            self.assertEqual(result['stop_reason'], 'MAPPED_SOURCE_UNAVAILABLE')


if __name__ == '__main__':
    unittest.main()
