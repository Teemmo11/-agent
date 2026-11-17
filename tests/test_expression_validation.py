import unittest
from spec_agent.spec.expressions import ExpressionValidator
from spec_agent.errors import AgentError
class ExpressionTests(unittest.TestCase):
    def test_valid(self):
        text,_=ExpressionValidator(['x','lo'],allow_result=True).validate('x >= lo && (result == x || result > lo)')
        self.assertIn('__sa_result',text)
    def test_reject_untrusted_syntax(self):
        for text in ['x=1','x++','system(x)','x; return 0','x/*a*/>0','*x','x[0]','(int)x','x / 0','x + 1','x -> y','x ? 1 : 0','01','2147483648']:
            with self.subTest(text=text),self.assertRaises(AgentError): ExpressionValidator(['x']).validate(text)
    def test_unknown_and_result_in_pre(self):
        for text in ['invented > 0','result > 0','__sa_result > 0']:
            with self.assertRaises(AgentError):ExpressionValidator(['x']).validate(text)
