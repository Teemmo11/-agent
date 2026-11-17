import tempfile
import unittest
import subprocess
import shutil
from pathlib import Path
from spec_agent.analysis.functions import CAnalyzer
from spec_agent.models import FormalContract,FormalEnsures
from spec_agent.spec.harness import emit_harness
from helpers import ROOT
class HarnessTests(unittest.TestCase):
    def test_snapshots_before_call_and_syntax(self):
        src=ROOT/'examples/clamp/program.c';f=CAnalyzer().analyze([src]).functions[0]
        q=FormalEnsures('Q1','(__sa_result >= __sa_old_low)','(x < low)')
        contract=FormalContract('FC','HS-1',f.function_id,'low <= high',[q],['low'],'hash','reqhash')
        with tempfile.TemporaryDirectory() as t:
            j=emit_harness(f,contract,q,[src],Path(t));text=Path(j.harness_file).read_text()
            self.assertLess(text.index('__sa_guard ='),text.index('__sa_result ='))
            self.assertLess(text.index('__sa_old_low ='),text.index('__sa_result ='))
            self.assertIn('!__sa_guard ||',text)
            self.assertEqual(text.count('__CPROVER_assert'),1)
            if shutil.which('gcc'):
                p=subprocess.run(['gcc','-fsyntax-only',j.harness_file],capture_output=True,text=True)
                self.assertEqual(p.returncode,0,p.stderr)
    def test_feasibility_has_no_function_call(self):
        src=ROOT/'examples/clamp/program.c';f=CAnalyzer().analyze([src]).functions[0]
        c=FormalContract('FC','HS-1',f.function_id,'low <= high',[],[],'hash','reqhash')
        with tempfile.TemporaryDirectory() as t:
            j=emit_harness(f,c,None,[src],Path(t));text=Path(j.harness_file).read_text()
            self.assertIn('__CPROVER_assert(0,',text);self.assertNotIn('clamp(',text)
    def test_c2btor_compatible_main_and_nondet(self):
        src=ROOT/'examples/clamp/program.c';f=CAnalyzer().analyze([src]).functions[0]
        q=FormalEnsures('Q1','(__sa_result >= __sa_old_low)','(x < low)')
        contract=FormalContract('FC','HS-1',f.function_id,'low <= high',[q],['low'],'hash','reqhash')
        with tempfile.TemporaryDirectory() as t:
            j=emit_harness(f,contract,q,[src],Path(t));text=Path(j.harness_file).read_text()
            for token in ['#define main __sa_original_main','#undef main','int __sa_entry(void)',
                          'int main(void)','return __sa_entry();','__CPROVER_nondet_']:
                self.assertIn(token,text)
            self.assertNotIn('__sa_nondet_',text)
            self.assertIn('extern int __CPROVER_nondet_x(void);',text)
            self.assertIn('int x = __CPROVER_nondet_x();',text)
    def test_source_defining_main_no_duplicate(self):
        with tempfile.TemporaryDirectory() as t:
            src=Path(t)/'prog.c'
            src.write_text('int clamp(int x, int low, int high) { return x < low ? low : (x > high ? high : x); }\n'
                           'int main(void) { return clamp(1, 0, 2); }\n')
            f=CAnalyzer().analyze([src]).functions[0]
            q=FormalEnsures('Q1','(__sa_result >= __sa_old_low)','(x < low)')
            contract=FormalContract('FC','HS-1',f.function_id,'low <= high',[q],['low'],'hash','reqhash')
            j=emit_harness(f,contract,q,[src],Path(t));text=Path(j.harness_file).read_text()
            self.assertNotIn('__sa_original_main(void)',text.split('#undef main',1)[1])
            self.assertEqual(text.count('int main(void)'),1)
            if shutil.which('gcc'):
                p=subprocess.run(['gcc','-fsyntax-only',j.harness_file],capture_output=True,text=True)
                self.assertEqual(p.returncode,0,p.stderr)
