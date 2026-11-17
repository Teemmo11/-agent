"""Explicit fake external executables: orchestration tests, NOT formal verification."""
import json
import os
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def fake_tools(directory,scenario='holds'):
    directory=Path(directory); directory.mkdir(parents=True,exist_ok=True)
    script='#!'+sys.executable+'\nSCENARIO = '+repr(scenario)+'\n'+r'''
import sys,json,re
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
flags='--goto-btor2 --goto-btor2-out --goto-btor2-map-out --function --property --inline --memory --array --no-standard-checks --show-properties --json-ui --bounds-check --pointer-check --div-by-zero-check --signed-overflow-check'
if SCENARIO.startswith('source_'):
 flags='--goto-btor2 --goto-btor2-out --goto-btor2-map-out --inline --memory --array --goto-btor2-checks --goto-btor2-no-slice-property --goto-btor2-no-lbe --bounds-check --pointer-check --div-by-zero-check --signed-overflow-check'
if SCENARIO.startswith('source_versioned'):
 flags+=' --goto-btor2-no-merge-bads --goto-btor2-no-optimize-state --goto-btor2-no-scalar-blocks --goto-btor2-scalar-slice --32 --64'
if '--help' in args:
 print(('C2BTOR 2.0.0 '+flags if SCENARIO.startswith(('c2btor_','source_')) else flags) if name in ('cbmc','c2btor') else 'check <model> portfolio' if name=='ric3' else 'catbtor <model>');sys.exit(0)
if '--version' in args: print('MOCK TOOL - NOT A FORMAL PROOF');sys.exit(0)
if name=='catbtor':
 if 'this is not BTOR2' in Path(args[0]).read_text(): print('invalid BTOR2',file=sys.stderr);sys.exit(1)
 if SCENARIO=='invalid': print('invalid model',file=sys.stderr);sys.exit(1)
 if SCENARIO=='mutate': Path(args[0]).write_text(Path(args[0]).read_text()+'; changed\n')
 sys.exit(0)
if name=='ric3':
 model=Path(args[1]); text=model.read_text()
 if 'spec_agent_model_boundaries' in text:
  print('SAT' if SCENARIO=='c2btor_boundary_sat' else 'UNKNOWN' if SCENARIO=='c2btor_boundary_unknown' else 'UNSAT');sys.exit(0)
 if SCENARIO in ('timeout','source_timeout'):
  import time;time.sleep(2)
 if SCENARIO=='crash': print('UNSAT');sys.exit(1)
 if SCENARIO=='conflict': print('SAT\nUNSAT');sys.exit(0)
 if SCENARIO in ('unknown','source_unknown'): print('UNKNOWN');sys.exit(0)
 if '; fixture-label:' not in text:
  print('SAT' if '2 one 1' in text else 'UNSAT');sys.exit(0)
 label=re.search(r'; fixture-label: (.*)',text)[1]
 raw='UNSAT'
 if 'P-FEASIBILITY' in label: raw='UNSAT' if SCENARIO in ('vacuous','source_vacuous') else 'SAT'
 elif SCENARIO in ('violated','source_violated') and label.endswith('.Q2'): raw='SAT'
 elif label=='main.array_bounds.1': raw='SAT'
 print(raw);sys.exit(0)
if name in ('cbmc','c2btor'):
 sources=[Path(x) for x in args if x.endswith('.c')]
 harness=next((p for p in sources if p.name=='harness.c'),None)
 if harness:
  text=harness.read_text(); lines=text.splitlines()
  i=next(i for i,l in enumerate(lines,1) if '__CPROVER_assert' in l)
  label=re.search(r'"([^"\n]+)"',lines[i-1])[1]
  prop='__sa_entry.assertion.1'; fn='__sa_entry'; klass='assertion'; file=str(harness)
 else:
  label='main.array_bounds.1';prop=label;fn=args[args.index('--function')+1] if '--function' in args else 'main';klass='array bounds';i=5;file=str(sources[0])
 if '--show-properties' in args:
  print(json.dumps([{'properties':[{'name':prop,'description':label,'class':klass,'sourceLocation':{'file':file,'line':str(i),'function':fn}}]}]));sys.exit(0)
 if '--goto-btor2' in args:
  if SCENARIO=='build_fail': print('compiler error',file=sys.stderr);sys.exit(1)
  model=Path(args[args.index('--goto-btor2-out')+1]);mapping=Path(args[args.index('--goto-btor2-map-out')+1])
  model.write_text('; MOCK FIXTURE, NOT GENERATED FROM C SEMANTICS\n; fixture-label: '+label+'\n1 sort bitvec 1\n2 zero 1\n3 bad 2\n'+('4 bad 2\n' if SCENARIO=='multi_bad' else ''))
  row={'kind':'ASSERT','property_id':prop,'property_class':klass,'bad_node':3,'source':{'file_name':file,'line':str(i),'function':fn}}
  if SCENARIO.startswith('source_'):
   if '--property' in args or '--goto-btor2-no-slice-property' not in args or '--goto-btor2-no-lbe' not in args:sys.exit(2)
   probe=sources[0].name=='probe.c'
   if not harness and not probe and '--goto-btor2-checks' not in args:sys.exit(2)
   source={k:v for k,v in row.items() if k!='kind'}
   source.update(bad_node=4,condition_node=2,pure_condition_node=2,elimination_reason='')
   aux=dict(source);aux.update(property_id='aux.assertion.1',bad_node=5,condition_node=3,pure_condition_node=3,
                               source={'file_name':file,'line':str(i+1),'function':fn})
   if probe:source.update(property_id='main.assertion.1',property_class='assertion')
   metadata={'format_version':'1','source_properties':[source,aux],
      'property_selection':{'merged':False,'scope':'all-goto-assertions','semantics':'selected-assertions-only','lifetime_top':'none'},
      'memory':{'frozen_on_violation':False,'proof_obligations':[],'properties':[]}}
   if SCENARIO.startswith('source_versioned'):
    if '--goto-btor2-no-merge-bads' not in args:sys.exit(2)
    bits=32 if '--32' in args else 64
    metadata.update(schema_version='c2btor-source-map-1',int_width=32,long_width=bits,long_long_width=64,pointer_width=bits,
      optimization_config={'array':'bv','memory':'object','lbe':False,'property_slicing':False,'merge_bads':False,
        'optimize_state':False,'scalar_blocks':False,'scalar_projection':'none','logical_arrays':False,'array_blocks':False,
        'array_loop_summary':False,'scalar_loop_summary':False,'symbolic_heap':False,'symbolic_heap_arrays':False,
        'symbolic_heap_wide_offsets':False,'symbolic_heap_compact':False,'symbolic_heap_bv_array_fallback':False})
    if SCENARIO=='source_versioned_ignored_policy':metadata['optimization_config']['optimize_state']=True
   model.write_text('; MOCK FIXTURE, NOT GENERATED FROM C SEMANTICS\n; fixture-label: '+label+'\n'+
      '; c2btor-property-contract selected-assertions-only\n1 sort bitvec 1\n2 zero 1\n3 one 1\n4 bad 2\n5 bad 3\n')
   if SCENARIO=='source_bad_probe' and probe:metadata['property_selection']['merged']=True
   mapping.write_text(json.dumps(metadata));sys.exit(0)
  if SCENARIO.startswith('c2btor_'):
   row['bad_node']=4
   source={k:v for k,v in row.items() if k!='kind'}
   source.update(condition_node=2,elimination_reason='unreachable_after_constant_folding' if SCENARIO=='c2btor_folded' else '')
   metadata={'format_version':'1','instructions':[] if SCENARIO=='c2btor_folded' else [row],
     'source_properties':[source],'property_selection':{'merged':SCENARIO=='c2btor_merged','property_ids':[] if SCENARIO=='c2btor_no_selection' else [prop]},
     'memory':{'frozen_on_violation':True,'proof_obligations':[{'pc':1,'condition_node':2,'property_class':'model_limit'}],
       'properties':[{'bad_node':5,'condition_node':2,'property_class':'model_limit'}]}}
   model.write_text('; MOCK FIXTURE, NOT GENERATED FROM C SEMANTICS\n; fixture-label: '+label+'\n'+
      ('' if SCENARIO=='c2btor_missing_contract' else '; c2btor-proof-contract 1\n')+
      '; c2btor-proof-obligation model_limit 2\n1 sort bitvec 1\n2 zero 1\n3 one 1\n4 bad 2\n5 bad 2\n')
   if SCENARIO=='c2btor_map_mismatch':metadata['memory']['proof_obligations'][0]['condition_node']=3
   mapping.write_text(json.dumps(metadata));sys.exit(0)
  if SCENARIO=='wrong_map': row['property_id']='other.assertion.1'
  mapping.write_text(json.dumps({'instructions':[row]}));sys.exit(0)
 print('unknown mock command',file=sys.stderr);sys.exit(2)
'''
    for name in ('cbmc','catbtor','ric3','c2btor'):
        p=directory/name;p.write_text(script);p.chmod(0o700)
    return str(directory)+os.pathsep+os.environ.get('PATH','')
