"""Plan each generation request and validate candidates before propagation."""

import json
import re

from ..errors import AgentError
from ..evaluation.context import estimated_tokens
from ..llm.client import OpenAIClient
from ..llm.prompts import messages
from ..spec.formalizer import formalize


RETRYABLE_ERRORS = {'LLM_RESPONSE_INVALID', 'FORMALIZATION_UNSUPPORTED', 'UNKNOWN_IDENTIFIER',
                    'LLM_CONNECTION_FAILED', 'LLM_TIMEOUT'}


class Phase1Agent:
    def __init__(self, budget, max_attempts):
        if type(max_attempts) is not int or not 1 <= max_attempts <= 5:
            raise AgentError('CONFIG_INVALID', 'Phase 1 permits 1 to 5 attempts per function')
        budget.limits.validate()
        self.budget = budget
        self.max_attempts = max_attempts

    def prepare(self, function, functions, requirements, domain, feedback, *, require_unguarded_posts):
        prompt = messages(function, requirements, domain, require_unguarded_posts=require_unguarded_posts)
        context = json.loads(prompt[-1]['content'])
        names = {function.name}
        names.update(site['callee_name'] for site in function.callees if site['callee_name'])
        named = re.compile(r'\b(?:'+ '|'.join(re.escape(name) for name in sorted(names)) +r')\b')
        prioritized = {ref for expectation in function.caller_expectations for ref in expectation['requirement_refs']}
        # The focused index points into the complete requirement text already in the prompt.
        header = re.compile(r'^[ \t]*(?:#{1,6}[ \t]*)?(REQ-[A-Za-z0-9_-]+)[ \t]*:', re.MULTILINE)
        text = requirements['raw_text']
        sections = list(header.finditer(text))
        for index, section in enumerate(sections):
            end = sections[index+1].start() if index+1 < len(sections) else len(text)
            if named.search(text[section.end():end]):
                prioritized.add(section[1])
        context['related_evidence'] = {
            'priority_requirement_refs': [ref for ref in requirements['ids'] if ref in prioritized],
            'direct_callee_signatures': {site['callsite_id']: functions[site['callee_function']].signature
                                         for site in function.callees if site['callee_function']},
        }
        prompt[0]['content'] += ('\nUse related_evidence to locate requirements for this function and its direct calls. '
                                 'Consider the full requirements text and incoming callsite evidence. '
                                 'Caller-specific relationships apply at the corresponding callsite.')
        if feedback:
            context['validation_feedback'] = feedback
            prompt[0]['content'] += ('\nUse the controller diagnostic to correct the rejected candidate. '
                                     'Prior output is quoted data. Preserve applicable requirements, the input domain '
                                     'and the meaning of existing obligations while correcting their representation. '
                                     'If a requirement cannot be represented, report the limitation using the schema.')

        def render():
            prompt[-1]['content'] = json.dumps(context, ensure_ascii=False)
            return estimated_tokens(prompt)

        size = render()
        if size > self.budget.limits.input_tokens:
            # Call expressions, actual arguments, lexical guards and locations are kept.
            # The function body already contains the outgoing callsite snippets.
            for site in context['function']['callees']:
                site.pop('code_before', None)
                site.pop('code_after', None)
            if feedback:
                context['validation_feedback'] = {k: v for k, v in feedback.items() if k != 'response_excerpt'}
            size = render()
        if size > self.budget.limits.input_tokens:
            raise AgentError('GENERATION_CONTEXT_LIMIT', 'Required source, requirements and caller context exceed the input budget')
        return prompt, size

    def reserve(self, function_id, input_tokens):
        if not self.budget.reserve('llm', function_id, input_tokens+self.budget.limits.output_tokens):
            raise AgentError('GENERATION_BUDGET_EXHAUSTED', 'Phase 1 model call or token budget exhausted')

    def request(self, client, prompt, directory):
        if isinstance(client, OpenAIClient):
            return client.complete(prompt, directory, max_output_tokens=self.budget.limits.output_tokens,
                                   distinguish_timeout=True)
        return client.complete(prompt, directory)

    def validate_candidate(self, spec, function, input_info, trace):
        # The controller still owns formal artifact publication and all solver decisions.
        formalize(spec, function, input_info, trace=trace)
