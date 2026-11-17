"""Canonical packaged schemas; reject unsupported validation keywords."""
import json
from pathlib import Path
from ..llm.schema import validate
from ..errors import AgentError

ALLOWED={'type','required','properties','additionalProperties','enum','items','minItems','maxItems',
         'minLength','maxLength','pattern'}


def assert_supported(schema):
    if set(schema)-ALLOWED:raise AgentError('EVALUATION_SCHEMA_INVALID','Unsupported schema keyword')
    for child in schema.get('properties',{}).values():assert_supported(child)
    if 'items' in schema:assert_supported(schema['items'])


def check(value,name):
    schema=json.loads((Path(__file__).parents[1]/'schemas'/(name+'.schema.json')).read_text(encoding='utf-8'))
    assert_supported(schema);validate(value,schema)
