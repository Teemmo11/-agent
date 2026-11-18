import json
import tempfile
import unittest
from pathlib import Path

from spec_agent.analysis.functions import CAnalyzer
from spec_agent.artifacts import sha256_file
from spec_agent.evaluation.models import Budget, Limits
from spec_agent.generators.llm_hoare import generate
from spec_agent.phase1.agent import Phase1Agent

from test_caller_propagation import DynamicClient


class Phase1AgentTests(unittest.TestCase):
    def generate_specs(self, root, client, *, attempts=3, limits=None):
        source = root/'program.c'
        source.write_text('int f(int x) { return x; }\nint main(void) { return f(2); }', encoding='utf-8')
        program = CAnalyzer().analyze([source])
        requirements = {'ids': ['REQ-1'], 'raw_text': 'REQ-1:\nmain and f return nonnegative values.'}
        agent = Phase1Agent(Budget(limits or Limits(calls_per_function=attempts)), attempts)
        result = generate(program, requirements, {'source_sha256': 's', 'requirements_sha256': 'r'},
                          client, root/'generation', agent=agent)
        return program, result, agent.budget

    def test_retries_json_and_expression_errors_before_propagating_caller_expectations(self):
        class Client(DynamicClient):
            def complete(self, messages, directory):
                candidate = super().complete(messages, directory)
                if len(self.contexts) == 1:
                    return '{ malformed'
                if len(self.contexts) == 2:
                    value = json.loads(candidate)
                    value['function_spec']['post_conditions'][0]['formal_candidate'] = 'unbound > 0'
                    value['callee_expectations'][0]['expected_post_nl'] = 'rejected expectation'
                    return json.dumps(value)
                return candidate

        with tempfile.TemporaryDirectory() as tmp:
            root, client = Path(tmp), Client()
            program, result, budget = self.generate_specs(root, client)
            self.assertEqual(result['failures'], [])
            self.assertEqual(budget.calls, 4)
            self.assertEqual(client.contexts[1]['validation_feedback']['error']['code'], 'LLM_RESPONSE_INVALID')
            feedback = client.contexts[2]['validation_feedback']
            self.assertEqual(feedback['error']['code'], 'UNKNOWN_IDENTIFIER')
            self.assertIn('(Q1)', feedback['error']['message'])
            context = client.contexts[3]
            self.assertEqual(context['related_evidence']['priority_requirement_refs'], ['REQ-1'])
            self.assertEqual(context['function']['callers'][0]['arguments'], ['2'])
            self.assertEqual([row['expected_post_nl'] for row in context['function']['caller_expectations']],
                             ['nonnegative result'])
            directory = root/'generation/functions'/program.order[0]
            attempts = json.loads((directory/'attempts.json').read_text(encoding='utf-8'))
            self.assertEqual(attempts['selected_attempt'], 3)
            self.assertEqual(len(attempts['attempts']), 3)
            self.assertEqual(sha256_file(directory/'prompt.json'), sha256_file(directory/'attempts/003/prompt.json'))
            self.assertIn('attempts/002/error.json', attempts['artifact_hashes'])

    def test_duplicate_response_stops_retries_and_context_limit_blocks_model_call(self):
        class Client(DynamicClient):
            def complete(self, messages, directory):
                super().complete(messages, directory)
                return '{ malformed'

        with tempfile.TemporaryDirectory() as tmp:
            _, result, budget = self.generate_specs(Path(tmp), Client())
            self.assertEqual(result['specs'], [])
            self.assertEqual([row['stop_reason'] for row in result['failures']], ['DUPLICATE_CANDIDATE']*2)
            self.assertEqual(budget.calls, 4)
        with tempfile.TemporaryDirectory() as tmp:
            client = Client()
            _, result, budget = self.generate_specs(Path(tmp), client, limits=Limits(input_tokens=512))
            self.assertEqual(result['specs'], [])
            self.assertEqual(result['failures'][0]['error']['code'], 'GENERATION_CONTEXT_LIMIT')
            self.assertEqual(client.contexts, [])
            self.assertEqual(budget.calls, 0)
