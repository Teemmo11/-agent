import json
import unittest
from pathlib import Path
from spec_agent.analysis.functions import CAnalyzer
from spec_agent.llm.parser import parse_response
from spec_agent.llm.prompts import SYSTEM,messages
from spec_agent.errors import AgentError
from helpers import ROOT
class ParserTests(unittest.TestCase):
    def setUp(self):
        self.p=CAnalyzer().analyze([ROOT/'examples/clamp/program.c']);self.f=self.p.functions[0]
        self.data=json.loads((ROOT/'examples/clamp/llm_fixture.json').read_text())['clamp']
    def parse(self): return parse_response(json.dumps(self.data),self.f,{'ids':['REQ-001']},self.p)
    def test_valid(self): self.assertEqual(len(self.parse()['function_spec']['post_conditions']),2)
    def test_generation_prompt_requires_bare_json(self):
        for requirement in ['Return exactly one valid JSON object','Do not use Markdown','Do not use code fences']:
            self.assertIn(requirement,SYSTEM)
        context=json.loads(messages(self.f,{'ids':['REQ-001']})[-1]['content'])
        self.assertEqual(context['output_instruction'],'Output exactly one valid JSON object only. No Markdown fences or prose.')
    def test_nested_call_evidence_prompt_distinguishes_incoming_and_outgoing_calls(self):
        program=CAnalyzer().analyze([ROOT/'examples/nested_fan/program.c'])
        function=next(f for f in program.functions if f.name=='target_speed')
        incoming={site['callsite_id'] for site in function.callers}
        outgoing={site['callsite_id'] for site in function.callees}
        expectation='EXP-'+next(iter(incoming))
        function.caller_expectations=[{'expectation_id':expectation}]
        context=json.loads(messages(function,{'ids':['REQ-002']})[-1]['content'])
        allowed=set(context['allowed_postcondition_evidence_refs'])
        self.assertEqual(allowed, incoming | {expectation,'REQ-002'})
        self.assertTrue(outgoing.isdisjoint(allowed))
    def test_no_fences(self):
        fenced='```json\n'+json.dumps(self.data)+'\n```'
        with self.assertRaises(AgentError) as error:parse_response(fenced,self.f,{'ids':['REQ-001']},self.p)
        self.assertEqual(error.exception.code,'LLM_RESPONSE_INVALID')
    def test_no_prose_before_json(self):
        text='Here is the requested JSON:\n'+json.dumps(self.data)
        with self.assertRaises(AgentError) as error:parse_response(text,self.f,{'ids':['REQ-001']},self.p)
        self.assertEqual(error.exception.code,'LLM_RESPONSE_INVALID')
    def test_unknown_provenance(self):
        self.data['function_spec']['requirement_refs']=['FAKE']
        with self.assertRaises(AgentError):self.parse()
    def test_duplicate_clause(self):
        self.data['function_spec']['post_conditions'][1]['clause_id']='Q1'
        with self.assertRaises(AgentError):self.parse()
    def test_wrong_shape(self):
        self.data['function_spec']['pre_condition']['formal_candidate']=10
        with self.assertRaises(AgentError):self.parse()
    def test_duplicate_json_keys(self):
        with self.assertRaises(AgentError):parse_response('{"x":1,"x":2}',self.f,{'ids':[]},self.p)
