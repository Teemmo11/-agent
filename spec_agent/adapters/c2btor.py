"""Strict C2Btor 2 proof-contract parsing and transition-preserving queries."""
import json
import re
from pathlib import Path
from ..errors import AgentError

CONTRACT='; c2btor-proof-contract 1'
OBLIGATION=re.compile(r'; c2btor-proof-obligation (memory_validity|model_limit) ([1-9][0-9]*)')
SOURCE_CONTRACT='; c2btor-property-contract selected-assertions-only'
SOURCE_PROFILE='c2btor-source-assertions'
SOURCE_SCHEMA='c2btor-source-map-1'

def validate_source_policy(data,caps):
    """Check emitted configuration, not just the flags we intended to pass."""
    from .cbmc import source_policy
    policy=source_policy(caps)
    if not policy: return
    if data.get('schema_version')!=policy['schema_version']:
        raise AgentError('MODEL_CONTRACT_INVALID','Missing or changed versioned source-map schema')
    actual=data.get('optimization_config',{})
    expected_keys=set(policy)-{'schema_version','data_model'}
    if not isinstance(actual,dict) or set(actual)!=expected_keys:
        raise AgentError('MODEL_CONTRACT_INVALID','Missing or unknown converter optimization fields')
    for key,value in policy.items():
        if key in ('schema_version','data_model'): continue
        if type(actual.get(key)) is not type(value) or actual[key]!=value:
            raise AgentError('MODEL_CONTRACT_INVALID','Converter policy mismatch: '+key)
    widths={'int_width':32,'long_long_width':64,'long_width':32 if policy['data_model']=='ILP32' else 64,
            'pointer_width':32 if policy['data_model']=='ILP32' else 64}
    if any(type(data.get(k)) is not int or data[k]!=v for k,v in widths.items()):
        raise AgentError('MODEL_CONTRACT_INVALID','Converter target data model mismatch')
    if data.get('format_version')!='1':
        raise AgentError('MODEL_CONTRACT_INVALID','Converter ignored disabled LBE')

def _unique_object(pairs):
    data={}
    for key,value in pairs:
        if key in data: raise ValueError('Duplicate map key')
        data[key]=value
    return data

def source_inventory(model,mapping):
    """Validate every source bad before permitting selection of any one of them."""
    try:
        lines=Path(model).read_text(encoding='utf-8').splitlines()
        data=json.loads(Path(mapping).read_text(encoding='utf-8'),object_pairs_hook=_unique_object)
        if 'schema_version' in data and data['schema_version']!=SOURCE_SCHEMA:
            raise ValueError('Unknown versioned source-map schema')
        if lines.count(SOURCE_CONTRACT)!=1 or any(line.startswith('; c2btor-proof-') for line in lines):
            raise ValueError('Missing or mixed source-assertions contract')
        if data.get('format_version') not in ('1','2'): raise ValueError('Unknown source-map version')
        if data['format_version']=='2' and not isinstance(data.get('blocks'),list):
            raise ValueError('LBE map lacks block provenance')
        selection=data['property_selection']
        if (selection.get('merged') is not False or selection.get('scope')!='all-goto-assertions' or
            selection.get('semantics')!='selected-assertions-only' or selection.get('lifetime_top')!='none'):
            raise ValueError('Unknown or merged source-property semantics')
        memory=data['memory']
        if (memory.get('frozen_on_violation') is not False or memory.get('proof_obligations')!=[] or
            memory.get('properties')!=[]):
            raise ValueError('Unexpected internal memory obligations')
        rows={}; bads={}; previous=0
        for line in lines:
            tokens=line.split(';',1)[0].strip().split()
            if not tokens: continue
            node=int(tokens[0])
            if node<=previous: raise ValueError('Non-increasing model IDs')
            previous=node; rows[node]=tokens
            if tokens[1]=='bad': bads[node]=int(tokens[2])
            if tokens[1:3]==['sort','array']: raise ValueError('rIC3 requires a pure BV model')
        booleans={node for node,row in rows.items() if row[1:]==['sort','bitvec','1']}
        props=data['source_properties']
        if not isinstance(props,list) or not props: raise ValueError('No source properties')
        declared=set(); identities=set()
        for prop in props:
            if not isinstance(prop,dict): raise ValueError('Malformed source property')
            pid=prop['property_id']; bad=prop['bad_node']; predicate=prop['condition_node']
            if not isinstance(pid,str) or not pid or pid in identities: raise ValueError('Ambiguous property ID')
            identities.add(pid)
            if (type(bad) is not int or type(predicate) is not int or bad<=0 or predicate<=0 or
                bad in declared or bads.get(bad)!=predicate or predicate not in rows):
                raise ValueError('Source property/bad mismatch')
            row=rows[predicate]
            if row[1] in ('sort','bad','output','constraint','init','next') or int(row[2]) not in booleans:
                raise ValueError('Source predicate must be one bit')
            if prop.get('pure_condition_node',predicate)!=predicate: raise ValueError('Impure source predicate')
            reason=prop.get('elimination_reason','')
            if reason not in ('','unreachable_after_constant_folding'):
                raise ValueError('Unknown source elimination reason')
            if reason and row[1]!='zero': raise ValueError('Unreachable property is not explicitly false')
            src=prop['source']
            if (not isinstance(src,dict) or not isinstance(src.get('file_name'),str) or not src['file_name'] or
                int(src['line'])<=0 or not isinstance(src.get('function'),str) or not src['function'] or
                not isinstance(prop.get('property_class'),str) or not prop['property_class']):
                raise ValueError('Missing source attribution')
            declared.add(bad)
        if set(bads)!=declared: raise ValueError('Undeclared source bad nodes')
        return lines,data
    except (OSError,ValueError,KeyError,TypeError,IndexError,AttributeError) as exc:
        raise AgentError('MODEL_CONTRACT_INVALID',str(exc)) from exc

def source_query(model,mapping,target,property_id):
    lines,data=source_inventory(model,mapping)
    matches=[p for p in data['source_properties'] if p['property_id']==property_id and p['bad_node']==target]
    if len(matches)!=1: raise AgentError('ATTRIBUTION_UNKNOWN','No unique requested source property')
    # Only declaration lines are removed. All dynamics/constraints/expressions
    # remain byte-for-byte by line; retained node IDs are never renumbered.
    keep=[]
    for line in lines:
        tokens=line.split(';',1)[0].strip().split()
        if tokens and len(tokens)>1 and tokens[1]=='bad' and int(tokens[0])!=target: continue
        keep.append(line)
    return '\n'.join(keep)+'\n',None,[]

def queries(model, mapping, target, property_id,profile='c2btor-2'):
    """Return single-property and single-OR boundary queries, never alter dynamics."""
    if profile==SOURCE_PROFILE: return source_query(model,mapping,target,property_id)
    if profile!='c2btor-2': raise AgentError('MODEL_CONTRACT_INVALID','Unknown converter contract profile')
    try:
        lines=Path(model).read_text(encoding='utf-8').splitlines(); data=json.loads(Path(mapping).read_text(encoding='utf-8'))
        if lines.count(CONTRACT)!=1 or data.get('format_version')!='1': raise ValueError('Missing/unknown proof contract')
        selection=data['property_selection']
        if selection.get('merged') is not False or selection.get('property_ids')!=[property_id]:
            raise ValueError('Converter did not select exactly the requested source property')
        rows={}; obligations=[]; bads={}; previous=0
        for line in lines:
            if line.startswith('; c2btor-proof-obligation'):
                m=OBLIGATION.fullmatch(line)
                if not m: raise ValueError('Malformed boundary obligation')
                obligations.append((m[1],int(m[2])))
            text=line.split(';',1)[0].strip()
            if not text: continue
            tokens=text.split(); node=int(tokens[0])
            if node<=previous: raise ValueError('Non-increasing model node IDs')
            previous=node; rows[node]=tokens
            if tokens[1]=='bad': bads[node]=int(tokens[2])
        booleans={n for n,r in rows.items() if r[1:]==['sort','bitvec','1']}
        def boolean_node(node):
            if type(node) is not int or node<=0 or node not in rows: raise ValueError('Missing predicate node')
            row=rows[node]
            if row[1] in ('sort','bad','output','constraint','init','next') or int(row[2]) not in booleans:
                raise ValueError('Predicate must be a one-bit expression')
        if not booleans: raise ValueError('Missing Boolean sort')
        props=data['source_properties']
        if not isinstance(props,list) or len(props)!=1: raise ValueError('Non-unique selected source property')
        prop=props[0]
        if prop['property_id']!=property_id or prop['bad_node']!=target or target not in bads:
            raise ValueError('Source query identity mismatch')
        if prop.get('elimination_reason','') not in ('','unreachable_after_constant_folding'):
            raise ValueError('Placeholder is not a source property')
        predicate=prop['condition_node']; boolean_node(predicate)
        if bads[target]!=predicate: raise ValueError('Selected bad predicate mismatch')
        if prop.get('elimination_reason')=='unreachable_after_constant_folding' and rows[predicate][1]!='zero':
            raise ValueError('Folded property is not explicitly false')
        memory=data['memory']
        if memory.get('frozen_on_violation') is not True: raise ValueError('Unknown boundary semantics')
        mapped=memory['proof_obligations']
        if not isinstance(mapped,list): raise ValueError('Malformed map obligations')
        expected=[(p['property_class'],p['condition_node']) for p in mapped]
        if obligations!=expected or len(set(obligations))!=len(obligations):
            raise ValueError('Map/model boundary contract mismatch')
        for _,node in obligations: boolean_node(node)
        auxiliary=memory['properties']
        if not isinstance(auxiliary,list): raise ValueError('Malformed auxiliary properties')
        declared={target}
        for p in auxiliary:
            if (p['property_class'],p['condition_node']) not in obligations: raise ValueError('Unbound auxiliary property')
            node=p['bad_node']
            if node:
                if bads.get(node)!=p['condition_node']: raise ValueError('Auxiliary bad mismatch')
                declared.add(node)
        if set(bads)!=declared: raise ValueError('Undeclared bad nodes')
        def keep(line):
            text=line.split(';',1)[0].strip().split()
            return not text or len(text)<2 or text[1]!='bad'
        base=[line for line in lines if keep(line)]
        source=[line for line in lines if keep(line) or int(line.split()[0])==target]
        boundary=None
        if obligations:
            sort=min(booleans); node=previous; condition=obligations[0][1]
            for value in dict.fromkeys(n for _,n in obligations[1:]):
                node+=1; base.append(f'{node} or {sort} {condition} {value}');condition=node
            node+=1; base.append(f'{node} bad {condition} spec_agent_model_boundaries')
            boundary='\n'.join(base)+'\n'
        return '\n'.join(source)+'\n',boundary,[{'kind':kind,'condition_node':node} for kind,node in obligations]
    except (OSError,ValueError,KeyError,TypeError,IndexError,AttributeError) as exc:
        raise AgentError('MODEL_CONTRACT_INVALID',str(exc)) from exc
