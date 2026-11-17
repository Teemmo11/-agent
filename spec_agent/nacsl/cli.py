"""Run N-to-ACSL, audit a sealed run, or resolve an evidence reference."""
import json
import os
from pathlib import Path

from ..config import load_config
from ..ir_ab.semantics import Invalid
from ..t3t4.cli import DEFAULT_LIBRARY
from ..t3t4.input import read_json
from .audit import audit
from .controller import default_limits, run
from .gateway import Ledger
from .trace import lookup


def register(commands):
    build = commands.add_parser('nacsl', help='Generate and review ACSL from frozen natural-language requirements')
    build.add_argument('--requirements', required=True)
    build.add_argument('--interface', required=True)
    build.add_argument('--output', default='runs/nacsl')
    build.add_argument('--libz3', default=os.environ.get('IR_AB_LIBZ3', DEFAULT_LIBRARY))
    build.add_argument('--timeout-ms', type=int, default=2500)
    build.add_argument('--aux-mode', choices=['on_failure', 'shadow'], default='on_failure')
    build.add_argument('--max-repairs', type=int, choices=range(3), default=2)
    build.add_argument('--max-calls', type=int, default=36)
    build.add_argument('--max-tokens', type=int, default=300000)
    build.add_argument('--max-queries', type=int, default=2048)
    mode = build.add_mutually_exclusive_group()
    mode.add_argument('--online', action='store_true', help='Enable requests to the configured language model')
    mode.add_argument('--fixture', help='Use staged offline responses from JSON')
    for name in ('nacsl-audit', 'nacsl-trace'):
        command = commands.add_parser(name, help='Read-only N/R/S/IR/ACSL evidence access')
        command.add_argument('--run', required=True)
        command.add_argument('--manifest-sha256')
        if name == 'nacsl-trace':
            command.add_argument('--item', required=True, help='R1, N:L1, V1:S:S1, V1:F1, or an evidence reference')


def dispatch(args):
    try:
        if args.command != 'nacsl':
            result = audit(args.run, args.manifest_sha256)
            if args.command == 'nacsl-trace' and result['integrity'] == 'PASS':
                result = lookup(read_json(Path(args.run)/'trace/index.json'), args.item)
            print(json.dumps(result, ensure_ascii=True, indent=2))
            return 2 if result.get('integrity') == 'FAIL' else 0
        ledger = Ledger(default_limits(args.max_calls, args.max_tokens, args.max_queries))
        options = {'config': load_config(Path(args.env))} if args.online else (
            {'fixture': read_json(args.fixture)} if args.fixture else {})
        root, result = run(args.requirements, args.interface, output=args.output, library=args.libz3,
                           aux_mode=args.aux_mode, timeout=args.timeout_ms, max_repairs=args.max_repairs,
                           ledger=ledger, **options)
        print(json.dumps({'run': str(root), **{k: result[k] for k in (
            'status', 'stop_reason', 'publication_eligible', 'source_integrity', 'alignment', 'conversion',
            'repair', 'implementation_verification')}}, ensure_ascii=True, indent=2))
        return 0 if result['publication_eligible'] else 130 if result['status'] == 'CANCELLED' else 2
    except (Invalid, KeyError, OSError) as exc:
        print(json.dumps({'status': 'ERROR', 'reason': getattr(exc, 'code', 'INPUT_NOT_FOUND')}))
        return 2
