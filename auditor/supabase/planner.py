"""Turn a SupabaseMap's relationships into a ready-to-run (or ready-to-
review) RLS/BOLA test plan, instead of you writing one `auditor rls
--table X --user-column Y ...` invocation by hand per table.

For a table with a direct owner column (orders.user_id, wallets.user_id)
this is a plain PostgREST filter. For a table that only owns a user
*indirectly* through another table (payments.order_id -> orders.user_id)
this builds a PostgREST embedded-resource filter so the single GET still
proves the same thing -- "can user A read user B's payment row" -- without
needing a payment ID at all, just the two users' own IDs.

Everything here produces plans and GET requests only. It never writes to
a table, alters a policy, or needs the schema itself to be writable.
"""
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from .audit import probe_cross_user_read


@dataclass
class PlannedCase:
    table: str
    kind: str  # "direct" | "chain" | "manual"
    owner_column: str | None
    owner_path: list | None
    path: str
    select: str | None
    filter_key: str | None
    confidence: str
    note: str = ""

    def as_dict(self):
        return asdict(self)


def _embed_select(owner_path, owner_column):
    """Recursively build a PostgREST embedded-resource select string, e.g.
    for a 2-hop chain payment_items -> payments -> orders(user_id):
    'payments!payment_id!inner(orders!order_id!inner(user_id))'.
    """
    def build(i):
        if i == len(owner_path):
            return owner_column
        hop = owner_path[i]
        return f"{hop['to_table']}!{hop['from_column']}!inner({build(i + 1)})"
    return build(0)


def _embed_filter_key(owner_path, owner_column):
    """The dot-path PostgREST uses to filter on an embedded column, e.g.
    'payments.orders.user_id' for the chain above.
    """
    return ".".join([hop["to_table"] for hop in owner_path] + [owner_column])


def build_case(candidate):
    """Turn one schema_map.py rls_candidate dict into a PlannedCase with a
    concrete PostgREST path/select/filter -- or a 'manual' case explaining
    why no safe automatic test could be built for that table.
    """
    table = candidate["table"]
    test = candidate.get("test")
    if test == "cross-user-select":
        owner_column = candidate["owner_column"]
        return PlannedCase(table, "direct", owner_column, [], f"/rest/v1/{table}", "*", owner_column, candidate.get("confidence", "high"))
    if test == "cross-user-select-chain":
        owner_path = candidate["owner_path"]
        owner_column = candidate["owner_column"]
        select = f"*,{_embed_select(owner_path, owner_column)}"
        filter_key = _embed_filter_key(owner_path, owner_column)
        chain_desc = " -> ".join([f"{h['from_table']}.{h['from_column']}" for h in owner_path] + [f"{owner_path[-1]['to_table']}.{owner_column}"])
        return PlannedCase(table, "chain", owner_column, owner_path, f"/rest/v1/{table}", select, filter_key, candidate.get("confidence", "medium"), note=f"ownership via {chain_desc}")
    return PlannedCase(table, "manual", None, None, f"/rest/v1/{table}", None, None, candidate.get("confidence", "medium"),
                        note="No owner column or relationship chain found within the hop limit; needs a manually-chosen pair of fixture object IDs instead of just --user-a/--user-b.")


def build_plan(smap, tables=None):
    """The full test plan: one PlannedCase per table in the schema map
    (optionally filtered to `tables`), in a stable, inspectable order.
    """
    wanted = set(tables) if tables else None
    cases = [build_case(c) for c in smap.rls_candidates if not wanted or c["table"] in wanted]
    return sorted(cases, key=lambda c: (c.kind != "direct", c.kind != "chain", c.table))


def plan_as_dict(smap, tables=None):
    return {"source": smap.source, "cases": [c.as_dict() for c in build_plan(smap, tables)]}


def write_plan(smap, path, tables=None):
    Path(path).write_text(json.dumps(plan_as_dict(smap, tables), indent=2), encoding="utf-8")


def run_sweep(client, reporter, smap, anon_key, token_a, token_b, user_a, user_b, tables=None):
    """Execute the whole plan: a GET cross-user probe per direct/chain
    case, using exactly the two user IDs you'd already use for any other
    two-account test on this project. Manual cases are reported, not
    skipped silently, so nothing in the schema goes unmentioned.
    """
    if not token_a or not token_b:
        raise ValueError("RLS sweep requires --token-a and --token-b")
    if not user_a or not user_b:
        raise ValueError("RLS sweep requires --user-a and --user-b")
    plan = build_plan(smap, tables)
    reporter.info(f"RLS sweep: {len(plan)} table(s) in plan ({sum(c.kind == 'direct' for c in plan)} direct, "
                  f"{sum(c.kind == 'chain' for c in plan)} chain, {sum(c.kind == 'manual' for c in plan)} manual).")
    for case in plan:
        if case.kind == "manual":
            reporter.info(f"{case.table}: skipped (manual review) -- {case.note}")
            continue
        params = {"select": case.select, "limit": "5", case.filter_key: f"eq.{user_b}"}
        probe_cross_user_read(client, reporter, case.table, case.path, params, anon_key, token_a, token_b, owner_path=case.filter_key, expected_owner_value=user_b)
