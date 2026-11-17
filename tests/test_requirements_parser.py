import unittest
from spec_agent.requirements.parser import parse_requirements
class RequirementsTests(unittest.TestCase):
    def test_ids_and_raw(self):
        text='REQ-001: one\nREQ-001: two\nREQ-OTHER: three'
        r=parse_requirements(text)
        self.assertEqual(r['ids'],['REQ-001','REQ-OTHER']);self.assertEqual(r['raw_text'],text)
    def test_stable_fallback(self):
        self.assertEqual(parse_requirements('x'),parse_requirements('x'))
        self.assertNotEqual(parse_requirements('x')['ids'],parse_requirements('y')['ids'])
