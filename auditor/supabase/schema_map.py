"""Read-only Supabase schema/relationship mapping.

Accepts an operator-supplied schema JSON or a PostgREST OpenAPI document
obtained with GET. It never attempts to alter policies, rows, or database
objects.
"""
import json
import re
from dataclasses import dataclass, asdict, field
from pathlib import Path

OWNER_HINTS = {"user_id", "owner_id", "seller_id", "vendor_id", "buyer_id", "created_by", "account_id", "profile_id"}
SEMANTIC_ALIASES = {"user": {"user", "profile", "profiles", "users"}, "profile": {"profile", "profiles", "user", "users"}, "seller": {"seller", "sellers", "vendor", "vendors"}, "vendor": {"vendor", "vendors", "seller", "sellers"}}
ENTITY_ALIASES = {
    "profiles":"profile", "users":"user", "orders":"order", "payments":"payment",
    "wallets":"wallet", "withdrawals":"withdrawal", "events":"event", "tickets":"ticket",
    "products":"product", "purchases":"purchase", "reviews":"review", "vendors":"vendor",
    "sellers":"seller", "accounts":"account", "transactions":"transaction",
}

@dataclass
class Column:
    name: str
    type: str = "unknown"
    nullable: bool = True

@dataclass
class Table:
    name: str
    columns: list[Column] = field(default_factory=list)
    owner_fields: list[str] = field(default_factory=list)
    primary_keys: list[str] = field(default_factory=list)

@dataclass
class Relationship:
    source_table: str
    source_column: str
    target_table: str
    target_column: str
    kind: str = "foreign-key"
    confidence: str = "medium"

@dataclass
class SupabaseMap:
    tables: list[Table] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    rls_candidates: list[dict] = field(default_factory=list)
    source: str = "schema"

    def as_dict(self):
        return asdict(self)

def _table_name_from_path(path):
    return str(path).strip("/").split("/")[0]

def _norm_entity(name):
    n = name.lower()
    return ENTITY_ALIASES.get(n, n[:-1] if n.endswith("s") else n)

def _parse_schema_json(data):
    """Support a small portable schema format:
    {"tables":{"orders":{"columns":{"id":"uuid","user_id":"uuid"},"primary_key":["id"]}}}
    Also accepts {"tables":[{"name":...,"columns":[...]}]}.
    """
    raw_tables = data.get("tables") if isinstance(data, dict) else None
    if isinstance(raw_tables, dict):
        items = []
        for name, spec in raw_tables.items():
            spec = spec if isinstance(spec, dict) else {}
            items.append((name, spec))
    elif isinstance(raw_tables, list):
        items = [(x.get("name"), x) for x in raw_tables if isinstance(x, dict) and x.get("name")]
    else:
        return []
    out=[]
    for name, spec in items:
        cols=[]
        raw_cols=spec.get("columns", {})
        if isinstance(raw_cols, dict):
            for cn, cv in raw_cols.items():
                if isinstance(cv, dict): cols.append(Column(cn, str(cv.get("type","unknown")), bool(cv.get("nullable",True))))
                else: cols.append(Column(cn, str(cv)))
        elif isinstance(raw_cols, list):
            for c in raw_cols:
                if isinstance(c, dict) and c.get("name"): cols.append(Column(str(c["name"]), str(c.get("type","unknown")), bool(c.get("nullable",True))))
                elif isinstance(c, str): cols.append(Column(c))
        pks=spec.get("primary_key", spec.get("primary_keys", []))
        if isinstance(pks,str): pks=[pks]
        owners=[c.name for c in cols if c.name.lower() in OWNER_HINTS or c.name.lower().endswith("_user_id")]
        out.append(Table(str(name), cols, owners, [str(x) for x in pks if x]))
    return out

def _infer_relationships(tables):
    names={t.name.lower():t.name for t in tables}
    rel=[]
    for t in tables:
        for c in t.columns:
            n=c.name.lower()
            if not n.endswith("_id") or n == "id": continue
            base=n[:-3]
            candidates=[base, base+"s"]
            target=None
            for cand in candidates:
                if cand in names: target=names[cand]; break
            if not target:
                # Common semantic aliases: user_id -> profiles/users, seller_id -> sellers/vendors
                for tn in names:
                    if _norm_entity(tn)==base or tn in SEMANTIC_ALIASES.get(base, set()):
                        target=names[tn]; break
            if target:
                target_table=next(x for x in tables if x.name==target)
                target_pk=target_table.primary_keys[0] if target_table.primary_keys else "id"
                conf="high" if target_pk in {"id", f"{base}_id"} else "medium"
                rel.append(Relationship(t.name,c.name,target,target_pk,confidence=conf))
    # dedupe
    seen=set(); out=[]
    for r in rel:
        k=(r.source_table,r.source_column,r.target_table,r.target_column)
        if k not in seen: seen.add(k); out.append(r)
    return out

def _resolve_owner_chain(start_table, tables_by_name, rel_by_source, max_hops=3):
    """BFS outward from start_table along foreign-key relationships looking
    for a table with a direct owner column -- e.g. payments (no owner
    column itself) -> orders (via order_id) -> has user_id.

    Returns (hops, owner_column) where hops is the list of Relationship
    objects traversed to get there, or (None, None) if nothing is found
    within max_hops. This is what lets the planner generate a safe
    cross-user test for tables like `payments` that only own a user
    indirectly through another table, instead of giving up on them.
    """
    start = tables_by_name.get(start_table.lower())
    if start and start.owner_fields:
        return [], start.owner_fields[0]
    visited = {start_table}
    frontier = [(start_table, [])]
    for _ in range(max_hops):
        next_frontier = []
        for table_name, path in frontier:
            for rel in rel_by_source.get(table_name, []):
                if rel.target_table in visited:
                    continue
                visited.add(rel.target_table)
                hops = path + [rel]
                target = tables_by_name.get(rel.target_table.lower())
                if target and target.owner_fields:
                    return hops, target.owner_fields[0]
                next_frontier.append((rel.target_table, hops))
        frontier = next_frontier
        if not frontier:
            break
    return None, None

def _build_rls_candidates(tables, relationships, max_hops=3):
    tables_by_name = {t.name.lower(): t for t in tables}
    rel_by_source = {}
    for r in relationships:
        rel_by_source.setdefault(r.source_table, []).append(r)
    candidates = []
    for t in tables:
        if t.owner_fields:
            for owner in t.owner_fields:
                candidates.append({"table": t.name, "owner_column": owner, "owner_path": [], "test": "cross-user-select", "requires": ["token_a", "token_b", "user_a", "user_b"], "safe_method": "GET", "confidence": "high"})
            continue
        hops, owner_column = _resolve_owner_chain(t.name, tables_by_name, rel_by_source, max_hops)
        if hops is not None and owner_column:
            owner_path = [{"from_table": h.source_table, "from_column": h.source_column, "to_table": h.target_table, "to_column": h.target_column} for h in hops]
            confidence = "high" if len(hops) == 1 else "medium"
            candidates.append({"table": t.name, "owner_column": owner_column, "owner_path": owner_path, "test": "cross-user-select-chain", "requires": ["token_a", "token_b", "user_a", "user_b"], "safe_method": "GET", "confidence": confidence})
        elif t.primary_keys:
            candidates.append({"table": t.name, "owner_column": None, "owner_path": None, "test": "manual-authorization-review", "requires": ["token_a", "token_b", "fixture_a", "fixture_b"], "safe_method": "GET", "confidence": "medium"})
    return candidates

def build_supabase_map_from_schema(data):
    tables=_parse_schema_json(data)
    rel=_infer_relationships(tables)
    candidates=_build_rls_candidates(tables, rel)
    return SupabaseMap(tables,rel,candidates,"schema")

def build_supabase_map_from_postgrest(doc):
    tables=[]
    paths=(doc or {}).get("paths",{}) if isinstance(doc,dict) else {}
    for path, detail in paths.items():
        name=_table_name_from_path(path)
        if not name or name.startswith("rpc/"): continue
        cols=[]; owners=[]
        # PostgREST OpenAPI commonly exposes definitions keyed by table name.
        definition=(doc.get("definitions",{}) or {}).get(name,{}) if isinstance(doc,dict) else {}
        props=definition.get("properties",{}) if isinstance(definition,dict) else {}
        for cn, cv in props.items():
            if not isinstance(cv,dict): cv={}
            cols.append(Column(cn,str(cv.get("type",cv.get("format","unknown")))))
            if cn.lower() in OWNER_HINTS or cn.lower().endswith("_user_id"): owners.append(cn)
        tables.append(Table(name,cols,owners,["id"] if "id" in props else []))
    # Some PostgREST versions omit definitions; retain discovered resource tables.
    unique={t.name:t for t in tables}
    result=SupabaseMap(list(unique.values()),[],[],"postgrest-openapi")
    result.relationships=_infer_relationships(result.tables)
    result.rls_candidates=_build_rls_candidates(result.tables, result.relationships)
    return result

def load_schema(path):
    data=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data,dict): raise ValueError("Supabase schema must be a JSON object")
    return build_supabase_map_from_schema(data)
