"""Independent one-shot proposals and deterministic diagnostics."""
import json
from pathlib import Path

from ..errors import AgentError
from ..evaluation.models import Budget
from ..ir_ab.semantics import Invalid, canon, digest
from ..llm.client import OpenAIClient
from ..llm.parser import strict_json
from ..trace import redact
from . import graph
from .checks import assess, compare, status
from .input import CANDIDATE, fragments, read_json


def candidate_context(frozen, schema):
    return {
        'S': frozen['S'], 'guards': frozen['guards'], 'schema': schema,
        'environment': {k: frozen[k] for k in ('signature', 'symbols', 'domain', 'rules')},
        'allowed': ['COPY', 'SPLIT_TOP_AND', 'BIND_EXISTING_GUARD', 'SAME_ROLE_AND_GROUP'],
        'fragments': {sid: fragments(row) for sid, row in frozen['S'].items()},
    }


def obtain(store, frozen, schema, *, fixture, cached, config, limits, client_factory=OpenAIClient, gateway=None):
    budget = Budget(limits)
    context = candidate_context(frozen, schema)
    identity = {'frozen_sha256': digest(frozen), 'context_sha256': digest(context), 'schema': CANDIDATE}
    mode = 'FIXTURE' if fixture else 'CACHED' if cached else gateway.mode if gateway else 'ONLINE' if config else 'NONE'
    info = {'mode': mode, 'status': 'NOT_RUN', 'online': 'NOT_RUN', 'binding': identity,
            'generation': 'ONE_SHOT', 'reason': 'NO_CANDIDATE'}
    if mode == 'NONE':
        return info, None
    directory = store.root / 'auxiliary'
    directory.mkdir(parents=True, exist_ok=True)
    try:
        if cached:
            envelope = read_json(cached)
            store.write('auxiliary/import.json', envelope)
            if envelope['binding'] != identity or envelope['response_sha256'] != digest(envelope['response']):
                raise Invalid('CANDIDATE_INPUT_MISMATCH')
            text = envelope['response']
            info['original_mode'] = envelope['mode']
        elif fixture:
            text = Path(fixture).read_text(encoding='utf-8')
        else:
            messages = [
                {'role': 'system', 'content': (
                    'Return exactly one JSON object matching the supplied candidate schema. '
                    'Keep every source obligation and role. Copy whole bodies or split only the outermost and. '
                    'A clause must explicitly give guard: null or the original guard name. '
                    'Use the supplied body AST, not a guard-expanded expression. '
                    'Use only provided source fragments. Do not emit commands or verdicts.')},
                {'role': 'user', 'content': canon(context)},
            ]
            if gateway:
                info['online'] = 'ATTEMPTED' if gateway.mode == 'ONLINE' else 'NOT_RUN'
                text = gateway.call('auxiliary', messages, directory)
                if gateway.mode == 'ONLINE':
                    info['online'] = 'RESPONSE_RECEIVED'
            else:
                tokens = len(json.dumps(messages, ensure_ascii=False).encode('utf-8'))
                if tokens > limits.input_tokens or not budget.reserve('llm', frozen['id'], tokens + limits.output_tokens):
                    raise Invalid('LLM_BUDGET_EXHAUSTED')
                store.write('auxiliary/request.json', redact(messages, (config.api_key,)))
                if config.llm_issues():
                    raise Invalid('LLM_CONFIG_MISSING')
                info['online'] = 'ATTEMPTED'
                text = client_factory(config).complete(messages, directory, max_output_tokens=limits.output_tokens,
                                                       distinguish_timeout=True)
                text = redact(text, (config.api_key,))
                info['online'] = 'RESPONSE_RECEIVED'
        (directory / 'response.txt').write_text(text, encoding='utf-8')
        store.write('auxiliary/candidate_binding.json', {
            'binding': identity, 'response': text, 'response_sha256': digest(text), 'mode': info.get('original_mode', mode),
        })
        candidate, names = graph.normalize(strict_json(text), frozen)
        store.write('auxiliary/normalization.json', names)
        store.write('auxiliary/graph.json', candidate)
        info.update(status='NORMALIZED', reason='CANDIDATE_RECEIVED')
        return info, candidate
    except (Invalid, AgentError, OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        code = getattr(exc, 'code', 'CANDIDATE_INVALID')
        unavailable = isinstance(exc, OSError) or code in (
            'LLM_TIMEOUT', 'LLM_CONNECTION_FAILED', 'LLM_HTTP_ERROR', 'LLM_CONFIG_MISSING', 'LLM_BUDGET_EXHAUSTED',
        )
        info.update(status='UNAVAILABLE' if unavailable else 'FAIL', reason=code)
        if info['online'] == 'ATTEMPTED':
            info['online'] = 'FAILED'
        return info, None
    finally:
        metadata = directory / 'response.metadata.json'
        if metadata.is_file():
            try:
                budget.charge(read_json(metadata))
            except (ValueError, TypeError, AttributeError):
                info['metadata_status'] = 'INVALID'
        info['budget'] = budget.snapshot()


def diagnose(main, main_graph, main_view, auxiliary, alternative, alternative_view, checks, frozen):
    main_ok = main['status'] == 'PASS'
    auxiliary_ok = auxiliary['status'] == 'PASS'
    alternative_checks = auxiliary.get('assessment', {})
    result = {
        'decision': 'MAIN_QUALIFIED' if main_ok else 'KEEP_MAIN_BLOCKED',
        'main_status': main['status'], 'auxiliary_status': auxiliary['status'],
        'main_issues': main.get('issues', []), 'auxiliary_issues': alternative_checks.get('issues', []),
        'source_alignment': {}, 'organization': None, 'difference': [], 'difference_status': 'NOT_RUN',
    }
    if alternative_view is not None and main_view is not None:
        for sid in frozen['S']:
            result['source_alignment'][sid] = {
                'main': [c['path'] for c in main_view['clauses'] if c['s_id'] == sid],
                'auxiliary': [c['path'] for c in alternative_view['clauses'] if c['s_id'] == sid],
            }
        result['organization'] = {
            'main': main_view['organization'], 'auxiliary': alternative_view['organization'],
        }
        if main['completeness'] == 'COMPLETE' and alternative_checks['completeness'] == 'COMPLETE':
            result['difference'] = compare(checks, 'diagnostics', main_view['pq'], alternative_view['pq'], {
                'main_sha256': main['graph_sha256'], 'auxiliary_sha256': digest(alternative),
                'S_P_sha256': digest([row for row in frozen['S'].values() if row['role'] == 'requires']),
            })
            result['difference_status'] = status(result['difference'])
            if main['semantics'] == alternative_checks['semantics'] == 'PASS' and result['difference_status'] == 'FAIL':
                result['decision'] = 'CHECK_CHAIN_CONFLICT'
    elif alternative is not None:
        result['structure_only'] = {
            'reason': 'GRAPH_NOT_DECODABLE',
            'main': {'root_ids': main_graph.get('roots'), 'node_ids': sorted(main_graph.get('nodes', {})),
                     'issues': result['main_issues']},
            'auxiliary': {'root_ids': alternative['roots'], 'node_ids': sorted(alternative['nodes']),
                          'issues': result['auxiliary_issues']},
        }
    if not main_ok and auxiliary_ok:
        result['suggestion'] = '检查主路径中首个失败步骤、对应 S 片段及规则配置。修复后创建新运行并全量验收。'
    if result['decision'] == 'CHECK_CHAIN_CONFLICT':
        result['suggestion'] = '复核两份图、冻结输入域、解码器及差分查询。'
    return result
