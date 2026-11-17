import tempfile
import unittest
from pathlib import Path
from spec_agent.analysis.functions import CAnalyzer
class CallgraphTests(unittest.TestCase):
    def test_top_down_context(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'p.c';p.write_text('int f(int x) { return x; }\nint main(void) { int x=2; if (x>0) { int y=f(x); return y; } return 0; }')
            r=CAnalyzer().analyze([p]);ids={f.name:f.function_id for f in r.functions}
            self.assertEqual(r.order,[ids['main'],ids['f']]);site=r.callsites[0]
            self.assertEqual(site['result_binding'],'y');self.assertEqual(site['arguments'],['x'])
            self.assertEqual(site['lexical_guards'],['x > 0']);self.assertEqual(r.functions[0].callers[0],site)
    def test_cycle_partial(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'p.c';p.write_text('int f(int x) { return f(x); }')
            r=CAnalyzer().analyze([p]);self.assertEqual(r.unresolved[0]['code'],'CYCLIC_EXPECTATIONS_PARTIAL')
