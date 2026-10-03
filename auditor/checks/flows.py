"""Declarative, read-only business-flow integrity checks.

The flow runner models relationships between resources without changing server state.
It is intentionally specification-driven: the tester supplies the endpoints and
field paths that matter to their application.
"""
import json
from pathlib import Path
from urllib.parse import quote
from ..core.models import Finding


def _get_path(data, path):
    cur = data
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None, False
    return cur, True


def _resolve(path, variables):
    for key, value in variables.items():
        path = path.replace("{" + key + "}", quote(str(value), safe=""))
    return path


def _token_for(name, tokens):
    token = tokens.get(name, "") if name else ""
    return token


def _fetch(client, path, token=""):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.request("GET", path, headers=headers, allow_redirects=False)


def run_flow(client, reporter, spec_path, token_a="", token_b=""):
    """Run a JSON flow specification using only GET requests.

    Spec shape:
      {
        "variables": {"order_a": "...", "payment_ref": "..."},
        "resources": [
          {"name":"order", "path":"/api/orders/{order_a}", "token":"a"},
          {"name":"payment", "path":"/api/payments/{payment_ref}", "token":"b"}
        ],
        "assertions": [
          {"type":"equal", "left":"order.data.amount", "right":"payment.data.amount"},
          {"type":"allowed_values", "resource":"order", "field":"data.status", "values":["pending","paid","cancelled"]},
          {"type":"equals", "resource":"order", "field":"data.owner_id", "value":"USER_A"}
        ]
      }
    """
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    variables = dict(spec.get("variables", {}))
    variables.setdefault("USER_A", variables.get("user_a", ""))
    variables.setdefault("USER_B", variables.get("user_b", ""))
    tokens = {"a": token_a, "b": token_b, "": ""}
    resources = {}
    for item in spec.get("resources", []):
        name = item.get("name")
        path = _resolve(item.get("path", ""), variables)
        if not name or not path:
            reporter.info("Skipped malformed flow resource")
            continue
        token = _token_for(item.get("token", ""), tokens)
        try:
            r = _fetch(client, path, token)
        except Exception as exc:
            reporter.info(f"Flow resource {name} failed: {exc}")
            continue
        body = None
        try:
            body = r.json()
        except Exception:
            body = {}
        resources[name] = {"status": r.status_code, "url": r.url, "body": body}
        reporter.info(f"Flow {name}: HTTP {r.status_code}")
        if r.status_code >= 500:
            reporter.add(Finding("MEDIUM", "business-logic", "Server error on business-flow read", f"GET {path} returned HTTP {r.status_code}.", "Review server-side validation and error handling for this resource flow.", r.url, confidence="medium", check_id="business.flow-server-error"))

    def value(ref):
        try:
            resource, field = ref.split(".", 1)
        except ValueError:
            return None, False
        if resource not in resources:
            return None, False
        return _get_path(resources[resource]["body"], field)

    for assertion in spec.get("assertions", []):
        kind = assertion.get("type")
        if kind == "equal":
            left, lok = value(assertion.get("left", "")); right, rok = value(assertion.get("right", ""))
            if lok and rok and left != right:
                reporter.add(Finding("HIGH", "business-logic", "Business-flow value mismatch", f"{assertion['left']}={left!r} differs from {assertion['right']}={right!r}.", "Compare server-side order totals, payment amounts and currencies before fulfillment; do not trust client-provided values.", None, confidence="high", check_id="business.flow-value-mismatch"))
        elif kind == "allowed_values":
            val, ok = value(f"{assertion.get('resource','')}.{assertion.get('field','')}")
            allowed = assertion.get("values", [])
            if ok and val not in allowed:
                reporter.add(Finding("MEDIUM", "business-logic", "Unexpected business state", f"{assertion.get('resource')}.{assertion.get('field')}={val!r} is outside the configured state set.", "Review server-side state transitions and reject invalid order/payment states.", resources.get(assertion.get("resource"), {}).get("url"), confidence="high", check_id="business.invalid-state"))
        elif kind == "equals":
            val, ok = value(f"{assertion.get('resource','')}.{assertion.get('field','')}")
            if ok and str(val) != str(_resolve(str(assertion.get("value", "")), variables)):
                reporter.add(Finding("HIGH", "business-logic", "Business-flow ownership/value assertion failed", f"Expected {assertion.get('resource')}.{assertion.get('field')} to equal the configured value, but observed {val!r}.", "Enforce ownership and authorization on the server for every object and state transition.", resources.get(assertion.get("resource"), {}).get("url"), confidence="medium", check_id="business.flow-assertion"))
        elif kind == "nonnegative":
            val, ok = value(f"{assertion.get('resource','')}.{assertion.get('field','')}")
            if ok:
                try:
                    if float(val) < 0:
                        reporter.add(Finding("HIGH", "business-logic", "Negative monetary/quantity value observed", f"{assertion.get('resource')}.{assertion.get('field')}={val!r}.", "Reject negative amounts and quantities server-side and validate numeric ranges before money movement or fulfillment.", resources.get(assertion.get("resource"), {}).get("url"), confidence="high", check_id="business.negative-value"))
                except (TypeError, ValueError):
                    reporter.add(Finding("MEDIUM", "business-logic", "Non-numeric monetary/quantity field", f"{assertion.get('resource')}.{assertion.get('field')} returned {val!r}.", "Validate monetary and quantity fields with strict server-side types and ranges.", resources.get(assertion.get("resource"), {}).get("url"), confidence="medium", check_id="business.numeric-validation"))
        elif kind == "transition":
            before, bok = value(f"{assertion.get('from_resource','')}.{assertion.get('field','status')}")
            after, aok = value(f"{assertion.get('to_resource','')}.{assertion.get('field','status')}")
            allowed = {tuple(x) for x in assertion.get("allowed", []) if isinstance(x, list) and len(x) == 2}
            if bok and aok and (before, after) not in allowed:
                reporter.add(Finding("HIGH", "business-logic", "Unexpected business state transition", f"Observed {before!r} -> {after!r}, which is not in the configured transition set.", "Model order/payment states as a server-side state machine and reject invalid transitions such as unpaid -> fulfilled or refunded -> paid unless explicitly supported.", resources.get(assertion.get("to_resource"), {}).get("url"), confidence="high", check_id="business.state-transition"))

    # Explicit authorization matrix. Both requests are GET-only and require two known identities.
    for check in spec.get("authorization", []):
        path_a = _resolve(check.get("path", ""), variables | {"id": check.get("id_a", "")})
        path_b = _resolve(check.get("path", ""), variables | {"id": check.get("id_b", "")})
        if not path_a or not path_b or not token_a or not token_b:
            continue
        try:
            ra = _fetch(client, path_b, token_a)
            rb = _fetch(client, path_a, token_b)
        except Exception as exc:
            reporter.info(f"Authorization matrix failed: {exc}")
            continue
        if ra.status_code == 200:
            reporter.add(Finding("HIGH", "authorization", "Cross-user object access may be possible", f"Token A received HTTP 200 for object B at {path_b}.", "Verify object ownership server-side and deny cross-user access; HTTP 404/403 is commonly appropriate depending on the application's design.", ra.url, confidence="high", check_id="business.cross-user-read"))
        if rb.status_code == 200:
            reporter.add(Finding("HIGH", "authorization", "Cross-user object access may be possible", f"Token B received HTTP 200 for object A at {path_a}.", "Verify object ownership server-side and deny cross-user access.", rb.url, confidence="high", check_id="business.cross-user-read"))
