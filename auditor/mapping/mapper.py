"""Read-only attack-surface mapping.

Builds a structured map from crawler output and optionally discovered OpenAPI
schemas. It never submits forms or mutates application state.
"""
import json
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

OPENAPI_CANDIDATES = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger/v1/swagger.json",
    "/api/openapi.json", "/api/schema", "/api/schema/openapi.json",
    "/api/docs/openapi.json", "/docs/openapi.json",
)
ID_SEGMENT = re.compile(r"^(?:[0-9a-f]{8,}|[0-9a-f]{32,}|[0-9a-f-]{36}|\d+)$", re.I)
ENTITY_WORDS = {"users":"user", "user":"user", "profiles":"profile", "profile":"profile",
                "orders":"order", "order":"order", "payments":"payment", "payment":"payment",
                "products":"product", "product":"product", "tickets":"ticket", "ticket":"ticket",
                "events":"event", "event":"event", "wallets":"wallet", "wallet":"wallet",
                "withdrawals":"withdrawal", "withdrawal":"withdrawal", "purchases":"purchase",
                "purchase":"purchase", "vendors":"vendor", "vendor":"vendor", "sellers":"seller",
                "seller":"seller", "reviews":"review", "review":"review",
                "votes":"vote", "vote":"vote", "polls":"poll", "poll":"poll",
                "ballots":"ballot", "ballot":"ballot", "candidates":"candidate", "candidate":"candidate",
                "contestants":"contestant", "contestant":"contestant", "nominees":"nominee", "nominee":"nominee",
                "elections":"election", "election":"election"}

@dataclass
class Endpoint:
    path: str
    methods: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source: str = "crawl"

@dataclass
class Entity:
    name: str
    paths: list[str] = field(default_factory=list)
    id_fields: list[str] = field(default_factory=list)
    likely_owner_fields: list[str] = field(default_factory=list)

@dataclass
class AttackMap:
    endpoints: list[Endpoint] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    relations: list[dict] = field(default_factory=list)
    openapi_url: str | None = None

    def as_dict(self):
        return asdict(self)

def _json(response):
    try: return response.json()
    except Exception: return None

def discover_openapi(client):
    """Find and parse a JSON OpenAPI document using GET only."""
    for path in OPENAPI_CANDIDATES:
        try:
            r = client.request("GET", path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        data = _json(r)
        if isinstance(data, dict) and ("openapi" in data or "swagger" in data) and isinstance(data.get("paths"), dict):
            return path, data
    return None, None

def _entity_from_segment(segment):
    clean = segment.strip("{}[]").lower()
    if clean in ENTITY_WORDS: return ENTITY_WORDS[clean]
    if clean.endswith("s") and clean[:-1] in ENTITY_WORDS: return ENTITY_WORDS[clean[:-1]]
    return None

def infer_entities(endpoints):
    entities = {}
    for ep in endpoints:
        parts = [p for p in ep.path.split("/") if p]
        for i, part in enumerate(parts):
            entity = _entity_from_segment(part)
            if not entity: continue
            e = entities.setdefault(entity, Entity(entity))
            if ep.path not in e.paths: e.paths.append(ep.path)
            following = parts[i+1:i+2]
            if following and (following[0].startswith("{") or ID_SEGMENT.match(following[0])):
                for fld in (f"{entity}_id", "id"):
                    if fld not in e.id_fields: e.id_fields.append(fld)
            for param in ep.parameters:
                pl = param.lower()
                if pl in {"user_id","owner_id","seller_id","vendor_id","created_by","created_by_id"} and pl not in e.likely_owner_fields:
                    e.likely_owner_fields.append(pl)
    return sorted(entities.values(), key=lambda x: x.name)

def _openapi_endpoints(doc):
    out=[]
    for path, item in doc.get("paths", {}).items():
        if not isinstance(item, dict): continue
        methods=[]; params=set(); tags=set()
        for method, op in item.items():
            if method.lower() not in {"get","post","put","patch","delete","head","options"} or not isinstance(op, dict): continue
            methods.append(method.upper())
            for p in op.get("parameters", []) or []:
                if isinstance(p, dict) and p.get("name"): params.add(str(p["name"]))
            tags.update(str(x) for x in op.get("tags", []) if x)
        if methods: out.append(Endpoint(path, sorted(set(methods)), sorted(params), sorted(tags), "openapi"))
    return out

def build_attack_map(client, site=None, include_openapi=True):
    endpoints=[]; seen=set()
    if site:
        for path in sorted(site.pages):
            if path.startswith(("/api/", "/auth/", "/graphql", "/rpc/")):
                key=(path, "GET")
                if key not in seen: endpoints.append(Endpoint(path,["GET"],sorted(site.params),[],"crawl")); seen.add(key)
    openapi_url=None
    if include_openapi:
        openapi_url, doc = discover_openapi(client)
        if doc:
            for ep in _openapi_endpoints(doc):
                key=(ep.path, tuple(ep.methods))
                if key not in seen: endpoints.append(ep); seen.add(key)
    entities=infer_entities(endpoints)
    relations=[]
    names={e.name for e in entities}
    for ep in endpoints:
        lower=ep.path.lower()
        touched=[n for n in names if re.search(rf"(?:^|/)s?{re.escape(n)}(?:/|$)", lower)]
        if len(touched)>=2:
            relations.append({"endpoint":ep.path,"entities":touched,"type":"co-occurrence"})
    return AttackMap(endpoints, entities, relations, openapi_url)
