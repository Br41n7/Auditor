from auditor.authorization.matrix import generate_candidates, _render

class E:
    def __init__(self, path, methods=("GET",)):
        self.path=path; self.methods=list(methods)

class M:
    endpoints=[E("/api/orders/{id}"), E("/api/users/{user_id}/orders/{id}"), E("/api/orders")]

def test_generate_candidates_only_get_with_placeholders():
    cs=generate_candidates(M())
    assert len(cs) == 2
    assert cs[0]["path"] == "/api/orders/{id}"
    assert "id:id" in cs[0]["requires"]

def test_render_requires_all_values():
    assert _render("/api/orders/{id}", {"id":"abc"}) == "/api/orders/abc"
    try:
        _render("/api/orders/{id}/{user_id}", {"id":"abc"})
        assert False
    except ValueError as exc:
        assert "user_id" in str(exc)
