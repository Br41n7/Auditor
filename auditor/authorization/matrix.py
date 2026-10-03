"""Read-only authorization matrix generation and execution.

The mapper proposes candidate object relationships. Execution is deliberately
limited to GET requests and requires two explicit authorized test accounts
plus concrete fixture IDs supplied by the operator.
"""
import json
import re
from pathlib import Path
from ..core.models import Finding

PLACEHOLDER = re.compile(r"\{([^{}]+)\}")
OWNER_HINTS = {"user", "owner", "seller", "vendor", "buyer", "created_by", "account", "profile"}


def _entity_for_path(path):
    parts = [p.strip("{}[]").lower() for p in path.split("/") if p]
    for p in parts:
        if p.endswith("s") and len(p) > 1:
            return p[:-1]
        if p in {"order", "payment", "product", "event", "ticket", "wallet", "withdrawal", "purchase", "review", "user", "profile", "seller", "vendor"}:
            return p
    return None


def generate_candidates(attack_map):
    """Return safe candidate cases; no network requests are made."""
    candidates = []
    for ep in attack_map.endpoints:
        if "GET" not in {m.upper() for m in ep.methods}:
            continue
        placeholders = PLACEHOLDER.findall(ep.path)
        if not placeholders:
            continue
        entity = _entity_for_path(ep.path)
        if not entity:
            continue
        # Prefer object IDs; nested user/owner IDs are still useful candidates
        # but are marked as needing explicit fixtures.
        confidence = "high" if any(p.lower() in {"id", f"{entity}_id"} for p in placeholders) else "medium"
        candidates.append({
            "name": f"{entity}-object-access",
            "path": ep.path,
            "entity": entity,
            "placeholders": placeholders,
            "confidence": confidence,
            "requires": ["token_a", "token_b"] + [f"id:{p}" for p in placeholders],
            "reason": "Object-level GET endpoint with path parameters can be tested for cross-account authorization.",
        })
    # Stable dedupe
    seen = set(); out = []
    for c in candidates:
        key = (c["path"], tuple(c["placeholders"]))
        if key not in seen:
            seen.add(key); out.append(c)
    return out


def load_fixture_map(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Fixture map must be a JSON object")
    return data


def _render(path, values):
    missing = []
    def repl(match):
        name = match.group(1)
        if name in values:
            return str(values[name])
        missing.append(name)
        return match.group(0)
    rendered = PLACEHOLDER.sub(repl, path)
    if missing:
        raise ValueError(f"Missing fixture values for placeholders: {', '.join(sorted(set(missing)))}")
    return rendered


def _status_ok(response):
    return response.status_code == 200 and bool((response.text or "").strip())


def run_case(client, reporter, case, token_a, token_b, fixture_a, fixture_b):
    path = case["path"]
    a_path = _render(path, fixture_a)
    b_path = _render(path, fixture_b)
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    try:
        a_own = client.request("GET", a_path, headers=headers_a, allow_redirects=False)
        a_cross = client.request("GET", b_path, headers=headers_a, allow_redirects=False)
        b_own = client.request("GET", b_path, headers=headers_b, allow_redirects=False)
    except Exception as exc:
        reporter.error(f"Matrix case {case.get('name', path)} failed: {exc}")
        return

    reporter.info(f"Matrix {case.get('name', path)}: A-own={a_own.status_code}, A-cross={a_cross.status_code}, B-own={b_own.status_code}")
    if _status_ok(a_own) and _status_ok(b_own) and _status_ok(a_cross):
        reporter.add(Finding(
            "HIGH", "authorization", "Reproduced cross-account object access",
            f"A can read its fixture ({a_own.status_code}), B can read its fixture ({b_own.status_code}), and A can also read B's fixture ({a_cross.status_code}) at {b_path}.",
            "Enforce object-level authorization using the authenticated principal and resource ownership before returning the object.",
            client.url(b_path), confidence="high", check_id="matrix.bola-read"))
    elif a_cross.status_code in (401, 403, 404):
        reporter.info(f"Matrix case denied cross-account access with HTTP {a_cross.status_code}.")
    else:
        reporter.info("Matrix case is inconclusive; inspect application semantics and response bodies manually.")


def run_matrix(client, reporter, spec_path, token_a, token_b):
    if not token_a or not token_b:
        raise ValueError("matrix execution requires --token-a and --token-b")
    data = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    cases = data.get("cases") if isinstance(data, dict) else None
    if not isinstance(cases, list) or not cases:
        raise ValueError("Matrix spec must contain a non-empty 'cases' array")
    for case in cases:
        if not isinstance(case, dict) or not case.get("path"):
            raise ValueError("Each matrix case requires a path")
        fixture_a = case.get("a") or {}
        fixture_b = case.get("b") or {}
        if not isinstance(fixture_a, dict) or not isinstance(fixture_b, dict):
            raise ValueError("Matrix case 'a' and 'b' must be objects of placeholder -> fixture ID")
        run_case(client, reporter, case, token_a, token_b, fixture_a, fixture_b)
