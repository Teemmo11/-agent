import argparse
import json
from pathlib import Path
from .config import load_config
from .artifacts import ArtifactStore
from .preflight import doctor
from .controller import run
from .errors import AgentError
from .trace import read_events, format_event

def main(argv=None):
    parser=argparse.ArgumentParser(description='Generate and verify function-level Hoare contracts')
    parser.add_argument('--env',default='.env',help='Configuration file; process environment wins')
    sub=parser.add_subparsers(dest='command',required=True)
    from .t3t4.cli import register as register_t3t4
    register_t3t4(sub)
    from .nacsl.cli import register as register_nacsl
    register_nacsl(sub)
    d=sub.add_parser('doctor'); d.add_argument('--output',default='runs')
    d.add_argument('--check-llm',action='store_true',help='Explicitly send one small real LLM request')
    d.add_argument('--probe-tools',action='store_true',help='Run real catbtor/rIC3 semantic smoke probes')
    a=sub.add_parser('audit');a.add_argument('--run',required=True,help='Run directory; checks REAL evidence only')
    e=sub.add_parser('evaluate',help='Independently assess specification quality')
    e.add_argument('--run',required=True);e.add_argument('--output',default='evaluations')
    e.add_argument('--reviewer',choices=['none','real','fixture'],default='none')
    e.add_argument('--review-fixture');e.add_argument('--logic',choices=['off','tools'])
    e.add_argument('--strength-cases',help='Evaluate P/Q strength and valid-input retention against labeled cases using real tools')
    e.add_argument('--reference-spec');e.add_argument('--require-real',action='store_true')
    e.add_argument('--max-queries',type=int,default=1000);e.add_argument('--max-llm-calls',type=int,default=64)
    e.add_argument('--max-input-tokens',type=int,default=16000);e.add_argument('--total-token-budget',type=int,default=128000)
    e.add_argument('--fail-on',choices=['INFO','LOW','MEDIUM','HIGH'],default='MEDIUM')
    ea=sub.add_parser('evaluation-audit',help='Read-only Phase 2 evidence audit')
    ea.add_argument('--evaluation',required=True);ea.add_argument('--parent-run')
    r=sub.add_parser('refine',help='Propose bounded, source-preserving specification revisions')
    r.add_argument('--evaluation',required=True);r.add_argument('--output',default='refinements')
    r.add_argument('--spec-id');r.add_argument('--max-iterations',type=int,default=2)
    r.add_argument('--proposer',choices=['real','fixture'],default='real');r.add_argument('--candidate-fixture')
    r.add_argument('--reviewer',choices=['none','real','fixture'],default='none');r.add_argument('--review-fixture')
    r.add_argument('--max-queries',type=int,default=1000);r.add_argument('--max-llm-calls',type=int,default=16)
    r.add_argument('--total-token-budget',type=int,default=128000);r.add_argument('--require-real',action='store_true')
    r.add_argument('--parent-run')
    ra=sub.add_parser('refinement-audit',help='Read-only refinement evidence audit')
    ra.add_argument('--refinement',required=True);ra.add_argument('--parent-run')
    logs=sub.add_parser('logs',help='Read/filter a run observation log without tool or LLM access')
    logs.add_argument('--run',required=True)
    logs.add_argument('--function-id'); logs.add_argument('--spec-id'); logs.add_argument('--property-id')
    logs.add_argument('--level',choices=['DEBUG','INFO','WARNING','ERROR'])
    logs.add_argument('--event',help='Exact event name')
    logs.add_argument('--json',action='store_true',help='Emit matching JSONL records')
    monitor=sub.add_parser('monitor',help='Read-only local graphical Phase 1 monitor')
    location=monitor.add_mutually_exclusive_group()
    location.add_argument('--run',help='Observe one run directory')
    location.add_argument('--runs',default='runs',help='Discover Phase 1 runs under this directory')
    monitor.add_argument('--port',type=int,default=8765,help='Loopback HTTP port; 0 chooses a free port')
    monitor.add_argument('--open',action='store_true',help='Open the local monitor in a browser')
    monitor.add_argument('--show-pq',action='store_true',help='Display Hoare preconditions and postconditions')
    for name in ('generate','run'):
        p=sub.add_parser(name); p.add_argument('--source',action='append',required=True)
        p.add_argument('--requirements',required=True); p.add_argument('--output',default='runs')
        p.add_argument('--require-real',action='store_true',help='Reject fixture/mock input; require compatible real tools and LLM configuration')
        p.add_argument('--llm-fixture',help='Recorded mock LLM responses; verification tools remain real')
        p.add_argument('--branch',choices=['both','hoare','static'],default='both')
        p.add_argument('--entry',help='CBMC static branch entry (default main or first extracted function)')
        p.add_argument('--domain-knowledge',help='Optional UTF-8 context file sent to LLM')
        p.add_argument('--log-max-mib',type=int,default=32,help='Maximum size per observation log (1..1024 MiB; default 32)')
        p.add_argument('--ui',action='store_true',help='Show graphical progress; keep monitor open after completion')
        p.add_argument('--ui-port',type=int,default=0,help='Monitor port; default chooses a free loopback port')
        p.add_argument('--ui-no-open',action='store_true',help='Print the monitor URL without opening a browser')
        p.add_argument('--show-pq',action='store_true',help='Display Hoare preconditions and postconditions in the monitor (requires --ui)')
    args=parser.parse_args(argv)
    try:
        if args.command in ('t3t4','t3t4-audit','t3t4-trace'):
            from .t3t4.cli import dispatch
            return dispatch(args)
        if args.command in ('nacsl','nacsl-audit','nacsl-trace'):
            from .nacsl.cli import dispatch
            return dispatch(args)
        if args.command=='monitor':
            from .monitor.server import serve
            root=Path(args.run or args.runs)
            if not root.is_dir() or not 0<=args.port<=65535:raise AgentError('CONFIG_INVALID','Monitor requires an existing directory and port 0..65535')
            return serve(root,port=args.port,single=bool(args.run),open_browser=args.open,show_pq=args.show_pq)
        if args.command=='logs':
            for record in read_events(Path(args.run)/'events.jsonl',function_id=args.function_id,
                                      spec_id=args.spec_id,property_id=args.property_id,
                                      level=args.level,event=args.event):
                print(json.dumps(record,ensure_ascii=False) if args.json else format_event(record),end='\n' if args.json else '')
            return 0
        if args.command=='audit':
            from .verification.audit import audit_run
            report=audit_run(Path(args.run));print(json.dumps(report,indent=2))
            return 0 if report['status']=='PASSED' else 2
        if args.command=='evaluation-audit':
            from .evaluation.audit import audit_evaluation
            report=audit_evaluation(args.evaluation,parent_root=args.parent_run);print(json.dumps(report,ensure_ascii=False,indent=2))
            return 0 if report['status']=='PASSED' else 2
        if args.command=='refinement-audit':
            from .refinement.audit import audit_refinement
            report=audit_refinement(args.refinement,parent_root=args.parent_run);print(json.dumps(report,ensure_ascii=False,indent=2))
            return 0 if report['status']=='PASSED' else 2
        c=load_config(Path(args.env))
        if args.command=='refine':
            from .refinement.controller import refine
            from .evaluation.models import Limits
            root,result=refine(args.evaluation,c,output=args.output,spec_id=args.spec_id,max_iterations=args.max_iterations,
                proposer=args.proposer,candidate_fixture=args.candidate_fixture,reviewer=args.reviewer,review_fixture=args.review_fixture,
                parent_root=args.parent_run,require_real=args.require_real,
                limits=Limits(calls_per_function=max(2,3*args.max_iterations),queries=args.max_queries,llm_calls=args.max_llm_calls,total_tokens=args.total_token_budget))
            print(f"{result['execution_status']} | decision={result['decision']} | stop={result['stop_reason']}")
            print('Refinement:',root/'refinement.json')
            return 130 if result['execution_status']=='CANCELLED' else 2 if result['execution_status']=='ERROR' else 3 if result['execution_status']=='PARTIAL' or result['decision']=='INCONCLUSIVE' else 1 if result['decision'] in ('REJECTED','NEEDS_REVIEW') else 0
        if args.command=='evaluate':
            from .evaluation.controller import evaluate
            from .evaluation.models import Limits
            from .evaluation.aggregate import exit_code
            limits=Limits(input_tokens=args.max_input_tokens,llm_calls=args.max_llm_calls,
                queries=args.max_queries,total_tokens=args.total_token_budget)
            if args.strength_cases:
                if args.reviewer!='none' or args.review_fixture or args.reference_spec or args.logic=='off':
                    raise AgentError('EVALUATION_CONFIG_INVALID','Strength cases require tool checks and cannot be combined with a reviewer or reference spec')
                from .evaluation.strength import evaluate_strength
                root,result=evaluate_strength(args.run,c,args.strength_cases,output=args.output,
                    require_real=args.require_real,limits=limits)
            else:
                root,result=evaluate(args.run,c,output=args.output,reviewer=args.reviewer,logic=args.logic or 'off',
                    review_fixture=args.review_fixture,require_real=args.require_real,reference_spec=args.reference_spec,limits=limits)
            if args.strength_cases:
                print(f"{result['execution_status']} | {result['stop_reason']} | parent={result['parent_run_id']}")
                for name,row in result.get('strength',{}).get('metrics',{}).items():
                    score='N/A' if row['score'] is None else f"{row['score']:.1%}"
                    count,label=(row['retained'],'retained') if name=='PreCorr' else (row['rejected'],'rejected')
                    print(f"{name}: {score} ({count}/{row['decided']} {label}, {row['undecided']} undecided) | {row['status']}")
            else:
                print(f"{result['execution_status']} | findings={len(result['findings'])} | parent={result['parent_run_id']}")
            print('Evaluation:',root/'evaluation.json');print('Report:',root/'report.md')
            return exit_code(result,args.fail_on)
        if args.command=='doctor':
            store=ArtifactStore(args.output); report=doctor(c,store.root,check_llm=args.check_llm,probe_tools=args.probe_tools)
            print(json.dumps(report,indent=2)); print('Artifacts:',store.root)
            return 0 if report['ready'] and report['llm']['configured'] and (not args.check_llm or report['llm']['connection_status']=='PASSED') else 2
        if not 1<=args.log_max_mib<=1024:
            raise AgentError('CONFIG_INVALID','--log-max-mib must be between 1 and 1024')
        if args.show_pq and not args.ui:
            raise AgentError('CONFIG_INVALID','--show-pq requires --ui for run and generate')
        ui=None
        try:
            if args.ui:
                from .monitor.server import Monitor
                if not 0<=args.ui_port<=65535:raise AgentError('CONFIG_INVALID','Monitor port must be 0..65535')
                ui=Monitor(args.output,port=args.ui_port,secrets=(c.api_key,),focused=True,
                           show_pq=args.show_pq).start(open_browser=not args.ui_no_open)
                print('Monitor:',ui.url,flush=True)
            root,result=run([Path(p) for p in args.source],Path(args.requirements),c,output=args.output,
              log_max_bytes=args.log_max_mib*1024*1024,require_real=args.require_real,generate_only=args.command=='generate',fixture=args.llm_fixture,branch=args.branch,entry=args.entry,
              domain=Path(args.domain_knowledge).read_text() if args.domain_knowledge else None,
              on_run_created=ui.attach if ui else None)
        except BaseException:
            if ui:ui.close()
            raise
        print(f"{result['status']} | {result['mode']} | evaluation=NOT_RUN")
        for row in result['contracts']:
            print(f"{row['function']}: P={row['precondition']['status']} contract={row['verification']['verdict']}")
            for q in row['properties']: print(f"  {q['property_id']}: {q['verdict']}")
        for row in result['static_properties']: print(f"static {row['cbmc_property_id']}: {row.get('verdict','NOT_RUN')}")
        print('Log:',root/'process.log', '|',result['logging']['status']); print('Failures:',len(result['failures'])); print('Result:',root/'result.json')
        if ui:
            try:
                if result['status']!='CANCELLED':
                    print('监控界面保持打开；Ctrl+C 关闭界面并返回本次运行退出码。',flush=True);ui.wait()
            finally:ui.close()
        if result['status']=='CANCELLED': return 130
        if result['status']!='COMPLETED': return 2
        if any(r['verification']['verdict']=='VIOLATED' for r in result['contracts']) or any(r.get('verdict')=='VIOLATED' for r in result['static_properties']): return 1
        if any(r['verification']['verdict'] in ('UNKNOWN','VACUOUS') for r in result['contracts']) or any(r.get('verdict')=='UNKNOWN' for r in result['static_properties']): return 3
        return 0
    except (AgentError,OSError) as exc:
        print(json.dumps({'status':'ERROR','error':exc.as_dict() if isinstance(exc,AgentError) else {'code':'INPUT_ERROR','message':str(exc)}}))
        return 2
