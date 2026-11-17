import tempfile
import unittest
from pathlib import Path
from spec_agent.analysis.functions import CAnalyzer
class AnalysisTests(unittest.TestCase):
    def analyze(self,text):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=Path(self.tmp.name)/'p.c';p.write_text(text)
        return CAnalyzer().analyze([p])
    def test_function_signature(self):
        p=self.analyze('/* docs */\nint f(int x) { return x; }')
        f=p.functions[0]
        self.assertEqual(f.signature,'int f(int x)');self.assertEqual(f.start_line,2)
        self.assertEqual(f.parameters[0].type,'int');self.assertEqual(f.harness_issues,[])
    def test_pointer_explicit_unsupported(self):
        p=self.analyze('int f(int *x) { return *x; }')
        self.assertTrue(p.functions[0].harness_issues)
    def test_macro_not_guessed(self):
        p=self.analyze('#define RET 1\nint f(void) { return RET; }')
        self.assertFalse(p.functions);self.assertEqual(p.unresolved[0]['code'],'ANALYSIS_UNSUPPORTED')
    def test_unresolved_call(self):
        p=self.analyze('int f(int x) { return unknown(x); }')
        self.assertEqual(p.unresolved[0]['code'],'UNRESOLVED_CALL')
        self.assertTrue(p.functions[0].harness_issues)
