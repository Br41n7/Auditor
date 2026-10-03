from auditor.supabase.schema_map import build_supabase_map_from_schema, build_supabase_map_from_postgrest

def test_schema_map_relationships_and_rls_candidates():
    m=build_supabase_map_from_schema({"tables":{
        "profiles":{"columns":{"id":"uuid"},"primary_key":["id"]},
        "orders":{"columns":{"id":"uuid","user_id":"uuid","payment_id":"uuid"},"primary_key":["id"]},
        "payments":{"columns":{"id":"uuid"},"primary_key":["id"]}
    }})
    assert any(r.source_table=='orders' and r.target_table=='profiles' for r in m.relationships)
    assert any(r.source_table=='orders' and r.target_table=='payments' for r in m.relationships)
    assert any(c['table']=='orders' and c['owner_column']=='user_id' for c in m.rls_candidates)

def test_postgrest_map_is_get_only_at_caller_contract():
    doc={'paths':{'orders':{},'profiles':{}},'definitions':{
        'orders':{'properties':{'id':{'type':'string'},'user_id':{'type':'string'}}},
        'profiles':{'properties':{'id':{'type':'string'}}}
    }}
    m=build_supabase_map_from_postgrest(doc)
    assert {t.name for t in m.tables} == {'orders','profiles'}
    assert any(c['table']=='orders' for c in m.rls_candidates)
