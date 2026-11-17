import unittest
from spec_agent.verification.conclusion import aggregate
class AggregateTests(unittest.TestCase):
    def test_truth_table(self):
        for p,qs,want in [('FEASIBLE',['HOLDS','HOLDS'],'HOLDS'),('FEASIBLE',['HOLDS','VIOLATED'],'VIOLATED'),
            ('INFEASIBLE',['HOLDS'],'VACUOUS'),('UNKNOWN',['HOLDS'],'UNKNOWN'),('ERROR',['HOLDS'],'ERROR'),
            ('FEASIBLE',['ERROR','VIOLATED'],'ERROR'),('FEASIBLE',['UNKNOWN'],'UNKNOWN'),('FEASIBLE',[],'UNKNOWN')]:
            with self.subTest(p=p,qs=qs):self.assertEqual(aggregate(p,[{'verdict':q} for q in qs]),want)
