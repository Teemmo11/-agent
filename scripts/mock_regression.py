#!/usr/bin/env python3
"""Persist reproducible mock evidence. The fake tools do NOT reason about C."""
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from helpers import fake_tools
from spec_agent.controller import run
from spec_agent.config import Config

def main():
    output=ROOT/'runs/mock-regression'
    from spec_agent.artifacts import ArtifactStore,write_json_atomic
    session=ArtifactStore(output)
    rows=[]
    for scenario,source,branch in [('holds','clamp/program.c','hoare'),('violated','clamp/buggy.c','hoare'),
            ('vacuous','clamp/program.c','hoare'),('holds','array_bug/program.c','static'),('holds','clamp/program.c','both')]:
        case=f'{len(rows):02d}-{scenario}'
        path=fake_tools(session.root/'fake-bin'/case,scenario)
        req=ROOT/'examples'/source.split('/')[0]/'requirements.md'
        with patch.dict(os.environ,{'PATH':path}):
            root,r=run([ROOT/'examples'/source],req,Config(tool_mode='MOCK'),output=session.root/case,
                fixture=ROOT/'examples/clamp'/('infeasible_fixture.json' if scenario=='vacuous' else 'llm_fixture.json') if branch!='static' else None,branch=branch)
        rows.append({'case':case,'source':source,'mode':r['mode'],'result':str(root/'result.json'),
          'contract_verdicts':[c['verification']['verdict'] for c in r['contracts']],
          'static_verdicts':[c['verdict'] for c in r['static_properties']]})
    report={'warning':'MOCK ONLY: programmed solver responses; no proof of input C correctness','cases':rows}
    write_json_atomic(session.root/'summary.json',report)
    print(json.dumps(report,indent=2));print('Report:',session.root/'summary.json')
if __name__=='__main__':main()
