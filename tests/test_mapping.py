from auditor.mapping.mapper import build_attack_map, discover_openapi
from auditor.core.output import Reporter

class R:
    def __init__(self, code=200, data=None):
        self.status_code=code; self._data=data; self.url='https://example.test/openapi.json'; self.text=''; self.headers={'content-type':'application/json'}
    def json(self):
        if self._data is None: raise ValueError()
        return self._data

class C:
    base_url='https://example.test/'
    def __init__(self):
        self.calls=[]
    def request(self, method, path, **kw):
        self.calls.append((method,path))
        if path == '/openapi.json':
            return R(data={'openapi':'3.0.0','paths':{'/api/orders/{id}':{'get':{'parameters':[{'name':'id','in':'path'}],'tags':['orders']}}, '/api/users/{id}/orders':{'get':{'parameters':[{'name':'id','in':'path'},{'name':'user_id','in':'query'}]}}}})
        return R(404)

def test_openapi_discovery_is_get_only():
    c=C(); url, doc=discover_openapi(c)
    assert url == '/openapi.json' and doc['openapi'] == '3.0.0'
    assert all(m == 'GET' for m,_ in c.calls)

def test_attack_map_infers_entities_and_owner_fields():
    c=C(); site=type('S', (), {'pages': {'/api/payments'}, 'js_files': set(), 'params': {'status'}})()
    m=build_attack_map(c, site)
    assert any(e.name == 'order' for e in m.entities)
    assert any('user_id' in e.likely_owner_fields for e in m.entities)
    assert any(ep.path == '/api/orders/{id}' for ep in m.endpoints)
