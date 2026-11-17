import unittest
from spec_agent.spec.expressions import ExpressionValidator
from spec_agent.errors import AgentError
class OldTests(unittest.TestCase):
    def test_scalar(self):
        text,snap=ExpressionValidator(['x'],allow_old=True,allow_result=True).validate('result == old(x)')
        self.assertIn('__sa_old_x',text);self.assertEqual(snap,['x'])
    def test_complex_rejected(self):
        for text in ['old(*x)','old(x[0])','old(foo())','old(result)']:
            with self.assertRaises(AgentError): ExpressionValidator(['x'],allow_old=True,allow_result=True).validate(text)
