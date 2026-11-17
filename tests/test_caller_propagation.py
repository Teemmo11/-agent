import json
import tempfile
import unittest
from pathlib import Path
from spec_agent.analysis.functions import CAnalyzer
from spec_agent.generators.llm_hoare import generate

class DynamicClient:
    mode='MOCK'
    def __init__(self): self.contexts=[]
    def complete(self,messages,directory):
        c=json.loads(messages[-1]['content']);self.contexts.append(c)
        f=c['function'];isroot=f['name']=='main'
        fs={'function':{'name':f['name'],'signature':f['signature']},'expected_behavior':'Required behavior',
          'pre_condition':{'natural_language':'any','formal_candidate':'1'},
          'post_conditions':[{'clause_id':'Q1','natural_language':'Nonnegative','formal_candidate':'result >= 0','guard':None,
              'requirement_refs':['REQ-1'],'evidence_refs':[]}],
          'requirement_refs':['REQ-1'],'conflicts':[],'ambiguities':[]}
        expectations=[{'callee':s['callee_name'],'callsite_id':s['callsite_id'],'expected_pre_nl':'nonnegative input',
          'expected_post_nl':'nonnegative result','requirement_refs':['REQ-1'],'evidence':['caller guard']} for s in f['callees']]
        return json.dumps({'function_spec':fs,'callee_expectations':expectations})

class CallerTests(unittest.TestCase):
    def test_propagation_uses_valid_callsites(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'p.c';p.write_text('int f(int x) { return x; }\nint main(void) { return f(2); }')
            program=CAnalyzer().analyze([p]);client=DynamicClient()
            r=generate(program,{'ids':['REQ-1'],'raw_text':'REQ-1 nonnegative'},
                {'source_sha256':'s','requirements_sha256':'r'},client,Path(t)/'generation')
            self.assertFalse(r['failures']);self.assertEqual(len(r['specs']),2)
            self.assertEqual(client.contexts[1]['function']['name'],'f')
            e=client.contexts[1]['function']['caller_expectations'][0]
            self.assertEqual(e['callsite_id'],program.callsites[0]['callsite_id'])
            self.assertEqual(r['specs'][1]['caller_expectation_refs'],[e['expectation_id']])
