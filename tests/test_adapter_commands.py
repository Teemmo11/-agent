"""Backend command compatibility for real BTOR2 pipeline; no verification claims."""
import unittest
from types import SimpleNamespace
from spec_agent.adapters.cbmc import BUILD_FLAGS,build_command
from spec_agent.adapters.ric3 import check_command
from spec_agent.errors import AgentError

def job():
    return SimpleNamespace(kind='HOARE_POSTCONDITION',generation_flags=[],source_files=['harness.c'],entry='__sa_entry')
CAPS={'cbmc_flags':BUILD_FLAGS+['--no-standard-checks']}

class CbmcBuildTests(unittest.TestCase):
    def test_build_command_flags(self):
        argv=build_command(job(),'model.btor2','map.json',CAPS,'__sa_entry.assertion.1')
        for token in ['--inline','--memory','object','--array','bv','--goto-btor2','--goto-btor2-map-out']:
            self.assertIn(token,argv)
        self.assertLess(argv.index('--inline'),argv.index('--goto-btor2'))
        self.assertLess(argv.index('--memory'),argv.index('--goto-btor2'))
        self.assertLess(argv.index('--array'),argv.index('--goto-btor2'))
        self.assertEqual(argv[argv.index('--memory')+1],'object')
        self.assertEqual(argv[argv.index('--array')+1],'bv')
    def test_entry_and_property_preserved(self):
        argv=build_command(job(),'model.btor2','map.json',CAPS,'__sa_entry.assertion.1')
        self.assertIn('--function',argv);self.assertIn('--property',argv)
        self.assertEqual(argv[argv.index('--function')+1],'__sa_entry')
        self.assertEqual(argv[argv.index('--property')+1],'__sa_entry.assertion.1')
    def test_missing_capability_rejected(self):
        with self.assertRaises(AgentError):
            build_command(job(),'model.btor2','map.json',{'cbmc_flags':[]},'p')

class Ric3CommandTests(unittest.TestCase):
    def test_portfolio_command(self):
        argv=check_command('model.btor2',{'ric3_profile':'btor-ric3-check-portfolio'})
        self.assertEqual(argv,['ric3','check','model.btor2','portfolio'])
        self.assertEqual(argv[-1],'portfolio')
    def test_wrong_profile_rejected(self):
        for profile in [None,'other']:
            with self.subTest(profile=profile):
                with self.assertRaises(AgentError): check_command('model.btor2',{'ric3_profile':profile})
