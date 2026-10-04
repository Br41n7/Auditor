import json
from auditor.core.output import Reporter
from auditor.supabase.schema_map import build_supabase_map_from_schema
from auditor.supabase.planner import build_plan, plan_as_dict, run_sweep


SCHEMA = {"tables": {
    "users": {"columns": {"id": "uuid"}, "primary_key": ["id"]},
    "orders": {"columns": {"id": "uuid", "user_id": "uuid"}, "primary_key": ["id"]},
    "wallets": {"columns": {"id": "uuid", "user_id": "uuid"}, "primary_key": ["id"]},
    "payments": {"columns": {"id": "uuid", "order_id": "uuid"}, "primary_key": ["id"]},
    "payment_items": {"columns": {"id": "uuid", "payment_id": "uuid"}, "primary_key": ["id"]},
}}


def _smap():
    return build_supabase_map_from_schema(SCHEMA)


def test_direct_owner_tables_get_a_plain_filter_case():
    plan = {c.table: c for c in build_plan(_smap())}
    assert plan["orders"].kind == "direct"
    assert plan["orders"].filter_key == "user_id"
    assert plan["orders"].select == "*"


def test_one_hop_chain_builds_embedded_select_and_filter():
    plan = {c.table: c for c in build_plan(_smap())}
    case = plan["payments"]
    assert case.kind == "chain"
    assert case.select == "*,orders!order_id!inner(user_id)"
    assert case.filter_key == "orders.user_id"


def test_two_hop_chain_builds_nested_embedded_select_and_filter():
    plan = {c.table: c for c in build_plan(_smap())}
    case = plan["payment_items"]
    assert case.kind == "chain"
    assert case.select == "*,payments!payment_id!inner(orders!order_id!inner(user_id))"
    assert case.filter_key == "payments.orders.user_id"


def test_table_with_no_owner_or_chain_is_manual():
    plan = {c.table: c for c in build_plan(_smap())}
    assert plan["users"].kind == "manual"


def test_tables_filter_narrows_the_plan():
    plan = build_plan(_smap(), tables=["orders", "wallets"])
    assert {c.table for c in plan} == {"orders", "wallets"}


def test_plan_as_dict_is_json_serializable():
    data = plan_as_dict(_smap())
    json.dumps(data)  # must not raise
    assert len(data["cases"]) == 5


class FakeResponse:
    def __init__(self, status_code, data):
        self.status_code = status_code
        self._data = data
        self.url = "https://example.test/rest/v1/x"

    def json(self):
        return self._data


class FakePostgrest:
    """Simulates: orders has a real cross-user leak (ignores caller,
    honors the client filter); wallets is correctly scoped server-side
    (always returns the caller's own row no matter what filter was sent)
    -- exactly the case that used to false-positive before verification
    was added.
    """
    base_url = "https://example.test/"
    ORDERS = [{"id": "o1", "user_id": "user-A"}, {"id": "o2", "user_id": "user-B"}]
    WALLETS = [{"id": "w1", "user_id": "user-A"}, {"id": "w2", "user_id": "user-B"}]

    def request(self, method, path, params=None, headers=None, **kw):
        token = (headers or {}).get("Authorization", "").replace("Bearer ", "")
        caller = {"token-a": "user-A", "token-b": "user-B"}.get(token)
        params = params or {}
        if path == "/rest/v1/orders":
            rows = self.ORDERS
            if "user_id" in params:
                wanted = params["user_id"].replace("eq.", "")
                rows = [r for r in rows if r["user_id"] == wanted]
            return FakeResponse(200, rows)
        if path == "/rest/v1/wallets":
            rows = [r for r in self.WALLETS if r["user_id"] == caller] if caller else []
            return FakeResponse(200, rows)
        return FakeResponse(200, [])


def test_sweep_flags_real_leak_but_not_a_server_that_ignores_the_filter():
    client = FakePostgrest()
    reporter = Reporter(quiet=True)
    smap = _smap()
    run_sweep(client, reporter, smap, anon_key="", token_a="token-a", token_b="token-b",
              user_a="user-A", user_b="user-B", tables=["orders", "wallets"])
    flagged_tables = {f.title for f in reporter.findings}
    assert any("orders" in t for t in flagged_tables)
    assert not any("wallets" in t for t in flagged_tables)


def test_sweep_requires_both_tokens_and_both_users():
    smap = _smap()
    reporter = Reporter(quiet=True)
    try:
        run_sweep(FakePostgrest(), reporter, smap, "", "", "token-b", "user-A", "user-B")
        assert False
    except ValueError as exc:
        assert "token" in str(exc)
    try:
        run_sweep(FakePostgrest(), reporter, smap, "", "token-a", "token-b", "", "user-B")
        assert False
    except ValueError as exc:
        assert "user" in str(exc)
