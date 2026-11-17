"""Lossless requirement spans. Citation coverage is not semantic coverage."""
import re
from ..artifacts import digest
from ..requirements.parser import parse_requirements


def index_requirements(text,checksum):
    lines=text.splitlines(keepends=True)
    headers=[]
    for i,line in enumerate(lines):
        match=re.match(r'^\s*(?:#{1,6}\s*)?(REQ-[A-Za-z0-9_-]+)\s*:(?:\s|$)',line)
        if match:headers.append((i,match[1]))
    if not headers:headers=[(0,parse_requirements(text)['ids'][0])]
    elif headers[0][0]>0:headers.insert(0,(0,'REQ-PREAMBLE-'+digest(text[:200])[:12]))
    items=[]
    for n,(start,rid) in enumerate(headers):
        end=headers[n+1][0] if n+1<len(headers) else len(lines)
        quote=''.join(lines[start:end])
        items.append({'item_id':'ITEM-'+digest(checksum+':'+str(start)+':'+str(end))[:16],
                      'requirement_id':rid,'start_line':start+1,'end_line':max(start+1,end),
                      'text':quote,'origin':'SOURCE_TEXT','sha256':checksum})
    return {'schema_version':1,'source_sha256':checksum,'items':items,
            'scope':'SOURCE_SPANS_NOT_ASSUMED_ATOMIC_BEHAVIORS'}
