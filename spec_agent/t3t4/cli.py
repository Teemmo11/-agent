"""CLI integration for staged construction, audit and trace lookup."""
import json
import os
from pathlib import Path

from ..config import load_config
from ..evaluation.models import Limits
from ..ir_ab.semantics import Invalid
from .audit import audit
from .controller import run
from .input import read_json
from .trace import lookup

DEFAULT_LIBRARY = '/lib/x86_64-linux-gnu/libz3.so.4'


def register(commands):
    run_parser = commands.add_parser('t3t4', help='Build and check a B contract, then emit verified ACSL')
    run_parser.add_argument('--input', required=True, help='Versioned R/S package')
    run_parser.add_argument('--material', help='Original UTF-8 requirement text')
    run_parser.add_argument('--output', default='runs/t3t4')
    run_parser.add_argument('--libz3', default=os.environ.get('IR_AB_LIBZ3', DEFAULT_LIBRARY))
    run_parser.add_argument('--timeout-ms', type=int, default=2500)
    run_parser.add_argument('--query-limit', type=int, default=1024)
    run_parser.add_argument('--policy', choices=['split', 'copy'], default='split')
    run_parser.add_argument('--max-steps', type=int)
    run_parser.add_argument('--aux-mode', choices=['on_failure', 'shadow'], default='on_failure')
    auxiliary = run_parser.add_mutually_exclusive_group()
    auxiliary.add_argument('--aux-fixture')
    auxiliary.add_argument('--aux-cached', help='Previously saved candidate_binding.json')
    auxiliary.add_argument('--aux-online', action='store_true', help='Enable at most one configured model request')
    run_parser.add_argument('--max-input-tokens', type=int, default=16000)
    run_parser.add_argument('--max-output-tokens', type=int, default=6144)
    run_parser.add_argument('--total-token-budget', type=int, default=32000)
    audit_parser = commands.add_parser('t3t4-audit', help='Read-only integrity and binding audit')
    audit_parser.add_argument('--run', required=True)
    audit_parser.add_argument('--manifest-sha256')
    trace_parser = commands.add_parser('t3t4-trace', help='Trace a requirement or artifact to its obligations and original text')
    trace_parser.add_argument('--run', required=True)
    trace_parser.add_argument('--manifest-sha256')
    key = trace_parser.add_mutually_exclusive_group(required=True)
    key.add_argument('--requirement')
    key.add_argument('--item', help='S ID, graph node ID, or relative evidence or step path')


def dispatch(args):
    try:
        if args.command == 't3t4':
            root, result = run(args.input, args.material, output=args.output, library=args.libz3,
                               timeout=args.timeout_ms, query_limit=args.query_limit, split=args.policy == 'split',
                               max_steps=args.max_steps, mode=args.aux_mode, fixture=args.aux_fixture,
                               cached=args.aux_cached, config=load_config(Path(args.env)) if args.aux_online else None,
                               limits=Limits(llm_calls=1, calls_per_function=1, input_tokens=args.max_input_tokens,
                                             output_tokens=args.max_output_tokens, total_tokens=args.total_token_budget))
            print(json.dumps({'run': str(root), 'status': result['status'], 'T3': result['main']['status'],
                              'T4': result['t4']['status'], 'auxiliary': result['auxiliary']['status'],
                              'online': result['auxiliary']['online']}, ensure_ascii=True, indent=2))
            return 0 if result['publication_eligible'] else 130 if result['status'] == 'CANCELLED' else 2
        result = audit(args.run, manifest_sha256=args.manifest_sha256)
        if args.command == 't3t4-trace' and result['integrity'] == 'PASS':
            result = lookup(read_json(Path(args.run) / 'trace/index.json'),
                            requirement=args.requirement, item=args.item)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 2 if result.get('integrity') == 'FAIL' else 0
    except (Invalid, KeyError, OSError) as exc:
        print(json.dumps({'status': 'ERROR', 'reason': getattr(exc, 'code', 'INPUT_NOT_FOUND')}))
        return 2
