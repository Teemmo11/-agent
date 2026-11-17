import re
from ..artifacts import digest

def parse_requirements(text):
    ids=list(dict.fromkeys(re.findall(r'\bREQ-[A-Za-z0-9_-]+',text)))
    return {'raw_text':text,'ids':ids or ['REQ-'+digest(text)[:12]]}
