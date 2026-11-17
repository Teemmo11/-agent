"""N-to-ACSL protocol, trace and release boundaries."""
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from spec_agent.ir_ab.semantics import Invalid, digest
from spec_agent.nacsl.audit import audit
from spec_agent.nacsl.controller import default_limits, run
from spec_agent.nacsl.domains import declarations
from spec_agent.nacsl.gateway import Ledger
from spec_agent.nacsl.protocol import parse_r, parse_s, source_lines
from spec_agent.nacsl.trace import lookup
from spec_agent.t3t4.cli import DEFAULT_LIBRARY
from spec_agent.t3t4.controller import run as downstream
from spec_agent.t3t4.controller import files
from spec_agent.artifacts import write_json_atomic
from spec_agent.t3t4.input import read_json

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples/nacsl'
LIB = Path(os.environ.get('IR_AB_LIBZ3', DEFAULT_LIBRARY))


class CoordinatesTests(unittest.TestCase):
    def test_invalid_operand_feedback_and_valid_unsupported_envelope(self):
        r = {'rows': [{'id': 'R1'}]}
        candidate = {'schema': 'nacsl-t2-1', 'status': 'OK', 'guards': {}, 'issues': [],
                     'S': [{'id': 'S1', 'role': 'ensures', 'expr': ['eq', 'result', ['amount', 'rate']],
                            'requirement_refs': ['R1']}]}
        with self.assertRaises(Invalid) as error:
            parse_s(candidate, r)
        self.assertEqual(error.exception.code, 'T2_OPERAND_TYPE')
        self.assertIn('$.S[0].expr[2]', error.exception.detail)
        candidate.update(status='UNSUPPORTED', S=[], issues=[
            {'kind': 'UNSUPPORTED', 'detail': 'Multiplication unsupported', 'refs': ['R:R1']}])
        self.assertEqual(parse_s(candidate, r)['status'], 'UNSUPPORTED')

    def test_exact_crlf_unicode_repeated_and_multispan(self):
        text = '🎛界限、界限。\r\n例外行\r\n'
        row = {'kind': 'REQUIREMENT', 'interpretation': '第二次符号加例外',
               'anchors': [{'line': 1, 'quote': '界限', 'occurrence': 2}, {'line': 2, 'quote': '例外行'}]}
        data = {'schema': 'nacsl-t1-1', 'items': [row], 'issues': []}
        parsed = parse_r(data, text)
        offsets = parsed['rows'][0]['spans']
        self.assertEqual(offsets[0]['start'], 4)
        self.assertEqual(offsets[1]['start'], source_lines(text)[1]['start'])
        self.assertEqual(text[offsets[1]['start']:offsets[1]['end']], '例外行')
        self.assertTrue(parsed['unclassified'])
        row['anchors'][0].pop('occurrence')
        with self.assertRaises(Invalid):
            parse_r(data, text)

    def test_conditional_numeric_expression_is_not_promoted_to_a_precondition(self):
        lines = source_lines('无故障时，状态为 1 或 2。\n状态为 0 到 3，信号为 0 或 1。')
        interface = {'parameters': ['state','signal'], 'parameter_aliases': {'状态':'state', '信号':'signal'}}
        found = declarations(interface, lines)
        self.assertEqual([row['ref'] for row in found], ['N:L2', 'N:L2'])
        self.assertEqual(found[0]['predicate'], ['and', ['ge','state',0], ['le','state',3]])


@unittest.skipUnless(LIB.is_file(), 'real Z3 library required')
class WorkflowTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.output = Path(temp.name)
        self.source = EXAMPLES/'access_decision.txt'
        self.interface = EXAMPLES/'access_decision.interface.json'
        self.good = read_json(EXAMPLES/'access_decision.fixture.json')
        self.repair = read_json(EXAMPLES/'access_repair.fixture.json')

    def execute(self, fixture, **options):
        return run(self.source, self.interface, output=self.output, library=LIB, fixture=fixture, **options)

    def test_domain_narrowing_is_blocked_but_other_caller_constraints_are_not_inferred(self):
        fixture = deepcopy(self.good)
        fixture['t2'][0]['S'][0]['expr'].append(['eq', 'level', 0])
        fixture['diagnosis'] = [{'schema': 'nacsl-diagnosis-1', 'proposals': []}]
        root, report = self.execute(fixture)
        self.assertEqual(report['stop_reason'], 'INPUT_DOMAIN_STRENGTHENED')
        self.assertFalse(report['publication_eligible'])
        self.assertEqual(audit(root)['integrity'], 'PASS', audit(root))
        self.assertEqual(report['versions'][0]['source_checks']['INPUT_DOMAIN_NOT_STRENGTHENED']['raw_result'], 'SAT')
        # A different explicit caller obligation is not implied by the range
        # recognizer. Do not incorrectly require D_N => the entire P.
        fixture = deepcopy(self.good)
        clause = '调用方还必须满足 level 小于 zone。'
        text = self.source.read_text(encoding='utf-8').rstrip() + '\n' + clause + '\n'
        extended = self.output/'extended.txt'
        extended.write_text(text, encoding='utf-8')
        fixture['t1'][0]['items'].append({'kind': 'REQUIREMENT', 'interpretation': clause,
                                         'anchors': [{'line': 5, 'quote': clause}]})
        fixture['t2'][0]['S'].append({'id': 'Caller', 'role': 'requires',
                                     'expr': ['lt', 'level', 'zone'], 'requirement_refs': ['R6']})
        self.source = extended
        root, report = self.execute(fixture)
        self.assertTrue(report['publication_eligible'], report)
        self.assertEqual(audit(root)['integrity'], 'PASS', audit(root))

    def test_partial_append_can_continue_to_second_repair(self):
        fixture = deepcopy(self.repair)
        fixture['t2'][0]['S'] = fixture['t2'][0]['S'][:-1]  # R4 and R5 absent
        f5 = deepcopy(fixture['alignment'][0]['findings'][0])
        f4 = {**f5, 'refs': ['R:R4'], 'fact': 'R4 missing'}
        fixture['alignment'].insert(0, {'schema': 'nacsl-alignment-1', 'findings': [f4, f5]})
        proposal = deepcopy(fixture['diagnosis'][0]['proposals'][0])
        proposal.update(finding_refs=['F1', 'F2'], evidence_refs=['R:R4', 'R:R5'])
        fixture['diagnosis'].insert(0, {'schema': 'nacsl-diagnosis-1', 'proposals': [proposal]})
        partial = deepcopy(fixture['repair'][0])
        partial['S'] = partial['S'][:-1]
        fixture['repair'].insert(0, partial)
        root, report = self.execute(fixture)
        self.assertTrue(report['publication_eligible'], report)
        self.assertEqual(len(report['versions']), 3)
        self.assertEqual(report['reviews'][1]['scope'], 'DRAFT_DIAGNOSTIC_ONLY')
        self.assertNotIn('downstream', report['versions'][1])
        self.assertEqual(audit(root)['integrity'], 'PASS', audit(root))
        _, limited = self.execute(fixture, max_repairs=1)
        self.assertEqual(limited['stop_reason'], 'REPAIR_LIMIT_EXHAUSTED')
        self.assertFalse(limited['publication_eligible'])

    def test_audit_reconstructs_review_context_even_after_manifest_reseal(self):
        root, report = self.execute(self.good)
        self.assertTrue(report['publication_eligible'], report)
        request_path = next(root.glob('agents/*-alignment/request.json'))
        request = read_json(request_path)
        import json
        context = json.loads(request[-1]['content'])
        context['input']['S'] = []
        request[-1]['content'] = json.dumps(context, ensure_ascii=False)
        write_json_atomic(request_path, request)
        call_path = request_path.with_name('call.json')
        call = read_json(call_path)
        call['request_sha256'] = digest(request)
        write_json_atomic(call_path, call)
        manifest = read_json(root/'manifest.json')
        manifest['files'] = files(root)
        write_json_atomic(root/'manifest.json', manifest)
        self.assertIn('ALIGNMENT_CONTEXT_BINDING', audit(root)['errors'])

    def test_actual_provider_budget_overrun_cannot_publish(self):
        ledger = Ledger(default_limits())
        # Simulate a final provider response exceeding reserved usage, without an API call.
        from spec_agent.nacsl.gateway import Gateway
        original = Gateway.call
        def call(gateway, stage, *args, **kwargs):
            result = original(gateway, stage, *args, **kwargs)
            if stage == 'alignment':
                gateway.ledger.charge({'usage': {'total_tokens': 300001}})
            return result
        with patch.object(Gateway, 'call', call):
            root, report = self.execute(self.good, ledger=ledger)
        self.assertEqual(report['stop_reason'], 'PROVIDER_TOKEN_BUDGET_EXCEEDED')
        self.assertFalse(report['publication_eligible'])
        self.assertEqual(audit(root)['integrity'], 'PASS', audit(root))

    def test_lossless_adapter_and_additive_repair_then_reapproval(self):
        root, report = self.execute(self.repair)
        self.assertTrue(report['publication_eligible'], report)
        self.assertEqual(report['repair'], 'ACCEPTED')
        self.assertEqual(report['implementation_verification'], 'NOT_RUN')
        self.assertEqual(report['versions'][0]['unmapped_R'], ['R5'])
        self.assertNotIn('downstream', report['versions'][0])
        self.assertEqual(report['reviews'][0]['scope'], 'DRAFT_DIAGNOSTIC_ONLY')
        last = report['versions'][-1]
        self.assertEqual(last['source_checks']['PRESERVE_OLD']['raw_result'], 'UNSAT')
        self.assertEqual(last['source_checks']['REPAIR_NOVELTY']['raw_result'], 'SAT')
        self.assertEqual(last['source_checks']['TOTAL_OUTPUT']['raw_result'], 'UNSAT')
        self.assertTrue(audit(root)['publication_eligible'], audit(root))
        req = lookup(read_json(root/'trace/index.json'), 'R5')['requirements']['R5']
        self.assertFalse(req['versions'][0]['obligations'])
        self.assertTrue(req['versions'][1]['obligations']['S4']['downstream']['output'])
        self.assertEqual(lookup(read_json(root/'trace/index.json'), 'V1:F1')['requirements'].keys(), {'R5'})
        self.assertEqual((root/last['downstream']['run']/'inputs/original.txt').read_bytes(), self.source.read_bytes())
        (root/'inputs/N.txt').write_bytes(b'changed')
        self.assertEqual(audit(root)['integrity'], 'FAIL')

    def test_input_domain_cannot_disappear_through_background_or_requires(self):
        background = deepcopy(self.good)
        background['t1'][0]['items'][0]['kind'] = 'BACKGROUND'
        background['t1'].append(deepcopy(background['t1'][0]))
        background['diagnosis'] = [{'schema':'nacsl-diagnosis-1','proposals':[]}]
        root, report = self.execute(background)
        self.assertEqual(report['stop_reason'], 'INPUT_DOMAIN_NOT_REQUIREMENT')
        self.assertEqual(report['source_integrity'], 'FAIL')
        self.assertEqual(report['alignment_scope'], 'DRAFT_DIAGNOSTIC_ONLY')
        self.assertFalse(list(root.glob('agents/*-t2')))
        self.assertFalse((root/'downstream').exists())
        self.assertEqual(audit(root)['integrity'], 'PASS', audit(root))

        omitted = deepcopy(self.good)
        omitted['t2'][0]['S'].pop(0)
        omitted['diagnosis'] = [{'schema':'nacsl-diagnosis-1','proposals':[]}]
        root, report = self.execute(omitted)
        self.assertEqual(report['stop_reason'], 'INPUT_DOMAIN_REQUIRES_MISSING')
        self.assertFalse((root/'downstream').exists())
        self.assertEqual(audit(root)['integrity'], 'PASS', audit(root))

    def test_true_p_with_correct_source_reference_is_not_enough(self):
        widened = deepcopy(self.good)
        widened['t2'][0]['S'][0]['expr'] = True
        widened['diagnosis'] = [{'schema':'nacsl-diagnosis-1','proposals':[]}]
        root, report = self.execute(widened)
        check = report['versions'][0]['source_checks']['INPUT_DOMAIN_PRESERVATION']
        self.assertEqual(report['stop_reason'], 'INPUT_DOMAIN_LOOSENED')
        self.assertEqual(check['raw_result'], 'SAT')
        self.assertEqual(check['witness_status'], 'REPLAYED')
        self.assertFalse((root/'downstream').exists())
        self.assertFalse(report['publication_eligible'])
        self.assertEqual(audit(root)['integrity'], 'PASS', audit(root))

    def test_retry_wrong_anchor_then_scope_protection(self):
        broken = deepcopy(self.repair)
        bad_r = deepcopy(broken['t1'][0])
        bad_r['items'][0]['anchors'][0]['quote'] = '无法匹配'
        broken['t1'].insert(0, bad_r)
        broken['repair'][0]['S'][0]['expr'] = True
        root, report = self.execute(broken)
        self.assertEqual(report['stop_reason'], 'REPAIR_PROTECTION')
        self.assertFalse(report['publication_eligible'])
        self.assertEqual(report['budget']['fixture_requests'], 6)
        self.assertEqual(read_json(root/'agents/001-t1/validation.json')['code'], 'ANCHOR_MISSING_OR_AMBIGUOUS')
        self.assertTrue((root/'versions/002/decision.json').is_file())
        self.assertEqual(audit(root)['integrity'], 'PASS', audit(root))

    def test_reviewer_fabricated_reference_and_budget(self):
        broken = deepcopy(self.good)
        broken['alignment'] = [deepcopy(self.repair['alignment'][0]) for _ in range(2)]
        for row in broken['alignment']:
            row['findings'][0]['refs'] = ['EV:made_up']
        _, report = self.execute(broken)
        self.assertEqual(report['stop_reason'], 'UNPROVIDED_REVIEW_REFERENCE')
        self.assertFalse(report['publication_eligible'])
        _, report = self.execute(self.good, ledger=Ledger(default_limits(calls=2)))
        self.assertEqual(report['stop_reason'], 'BUDGET_EXHAUSTED')
        self.assertEqual(report['budget']['fixture_requests'], 2)
        _, report = self.execute(self.good, ledger=Ledger(default_limits(queries=1)))
        self.assertEqual(report['stop_reason'], 'BUDGET_EXHAUSTED')
        self.assertEqual(report['budget']['queries'], 1)

    def test_real_conflict_and_unknown_gate(self):
        broken = deepcopy(self.good)
        broken['t2'][0]['S'].append({'id': 'S5', 'role': 'ensures', 'expr': False, 'requirement_refs': ['R1']})
        broken['diagnosis'] = [{'schema': 'nacsl-diagnosis-1', 'proposals': []}]
        root, report = self.execute(broken)
        self.assertEqual(report['stop_reason'], 'CONTRACT_CONFLICT')
        self.assertFalse((root/'downstream').exists())
        self.assertFalse(report['publication_eligible'])
        self.assertIn('R1', lookup(read_json(root/'trace/index.json'), 'V1:EV:P_Q_CONSISTENCY')['requirements'])
        with patch('spec_agent.t3t4.checks.Solver.run_raw', return_value=('unknown\n', [])):
            _, report = self.execute(broken)
        self.assertEqual(report['status'], 'TOOL_ERROR')

    def test_corrupted_t3_and_t4_route_without_rewriting_source(self):
        fixture = deepcopy(self.good)
        fixture['diagnosis'] = [{'schema': 'nacsl-diagnosis-1', 'proposals': []}]

        def invalid_graph(step, graph):
            if step == 2:
                graph['roots'].clear()
            return graph

        def invalid_output(root):
            path = root / 't4/contract.c'
            lines = path.read_text(encoding='utf-8').splitlines()
            lines.pop(next(i for i, line in enumerate(lines) if 'ensures' in line))
            path.write_text('\n'.join(lines)+'\n', encoding='utf-8')

        for options, t3, t4 in [({'inject': invalid_graph}, 'FAIL', 'NOT_RUN'),
                                 ({'output_inject': invalid_output}, 'PASS', 'FAIL')]:
            with self.subTest(t3=t3, t4=t4), patch('spec_agent.nacsl.controller.convert') as convert:
                convert.side_effect = lambda *a, **k: downstream(*a, **k, **options)
                root, report = self.execute(fixture)
                self.assertEqual(report['downstream']['T3'], t3)
                self.assertEqual(report['downstream']['T4'], t4)
                self.assertFalse(report['publication_eligible'])
                self.assertEqual(report['versions'][0]['S'], 't2/S.json')
                self.assertFalse((root/'versions/002').exists())
