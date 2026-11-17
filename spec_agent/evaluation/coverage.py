"""Bidirectional requirement inventory; never equate citation counts to meaning."""


def inventory(index,specs,functions):
    rows=[]
    for item in index['items']:
        links=[{'spec_id':s['spec_id'],'clause_id':q['clause_id']} for s in specs
               for q in s['function_spec']['post_conditions'] if item['requirement_id'] in q['requirement_refs']]
        rows.append({'requirement_item_id':item['item_id'],'requirement_id':item['requirement_id'],
                     'links':links,'citation_status':'REFERENCED' if links else 'UNREFERENCED',
                     'coverage_status':'UNCLEAR' if links else 'MISSING','evidence_kind':'DETERMINISTIC',
                     'limitations':['引用清单不等于语义覆盖。']})
    generated={s['function_id'] for s in specs}
    return {'rows':rows,'functions_without_specs':[f.function_id for f in functions if f.function_id not in generated],
            'citation_counts':{'items':len(rows),'referenced':sum(bool(r['links']) for r in rows)},
            'semantic_coverage_percentage':None,'scope':'BUSINESS_REQUIREMENTS; STATIC_SAFETY_REPORTED_SEPARATELY'}


def apply_reviews(coverage,reviews):
    # Keep each local judgment. A local SUPPORTED judgment cannot cover unrelated clauses/functions.
    for row in coverage['rows']:
        judgments=[]
        for review in reviews:
            for assessment in review.get('coverage',[]):
                if assessment['requirement_item_id']==row['requirement_item_id']:
                    judgments.append(dict(spec_id=review['spec_id'],**assessment))
        row['semantic_judgments']=judgments
        if not judgments:continue
        states={a['coverage_status'] for a in judgments}
        row['coverage_status']=next(iter(states)) if len(states)==1 else 'UNCLEAR'
        row['evidence_kind']='LLM_JUDGMENT'
    return coverage
