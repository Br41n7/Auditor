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

def build_supabase_map_from_schema(data):
    tables=_parse_schema_json(data)
    rel=_infer_relationships(tables)
    candidates=[]
    for t in tables:
        if t.owner_fields:
            for owner in t.owner_fields:
                candidates.append({"table":t.name,"owner_column":owner,"test":"cross-user-select","requires":["token_a","token_b","user_a","user_b"],"safe_method":"GET","confidence":"high"})
        elif t.primary_keys:
            candidates.append({"table":t.name,"owner_column":None,"test":"manual-authorization-review","requires":["token_a","token_b","fixture_a","fixture_b"],"safe_method":"GET","confidence":"medium"})
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
    for t in result.tables:
        for owner in t.owner_fields:
            result.rls_candidates.append({"table":t.name,"owner_column":owner,"test":"cross-user-select","requires":["token_a","token_b","user_a","user_b"],"safe_method":"GET","confidence":"high"})
    return result

def load_schema(path):
    data=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data,dict): raise ValueError("Supabase schema must be a JSON object")
    return build_supabase_map_from_schema(data)
