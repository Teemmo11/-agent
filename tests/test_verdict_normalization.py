import unittest
from types import SimpleNamespace
from spec_agent.adapters.ric3 import normalize
class VerdictTests(unittest.TestCase):
    def cmd(self,**kw):return SimpleNamespace(**{'spawn_error':None,'resource_limit':None,'timed_out':False,'returncode':0,**kw})
    def test_raw(self):
        self.assertEqual(normalize(self.cmd(),'UNSAT\n','')[:2],('HOLDS','UNSAT'))
        self.assertEqual(normalize(self.cmd(),'SAT\n','')[:2],('VIOLATED','SAT'))
    def test_no_substring_guess(self):
        for out,err in [('maybe UNSAT',''),('SAT\nUNSAT',''),('','UNSAT'),('UNSAT','unsupported')]:
            self.assertEqual(normalize(self.cmd(),out,err)[0],'ERROR')
    def test_exit_and_timeout(self):
        self.assertEqual(normalize(self.cmd(returncode=1),'UNSAT','')[0],'ERROR')
        self.assertEqual(normalize(self.cmd(timed_out=True),'UNSAT','')[0],'UNKNOWN')
    def test_panic_unknown_and_unparseable_never_hold(self):
        cases=[
            (self.cmd(),'','thread panicked at solver.rs:1'),
            (self.cmd(),'UNKNOWN\n',''),
            (self.cmd(),'not a solver result\n',''),
        ]
        for cmd,stdout,stderr in cases:
            with self.subTest(stdout=stdout,stderr=stderr):
                self.assertNotEqual(normalize(cmd,stdout,stderr)[0],'HOLDS')
    def test_portfolio_unsat_with_child_panic_and_zero_exit_is_error(self):
        stderr="thread 'main' panicked at src/transys/certify.rs:228:19:\nno entry found for key\n"
        self.assertEqual(normalize(self.cmd(returncode=0),'UNSAT\n',stderr),
                         ('ERROR',None,'RIC3_FAILED'))
