from urllib.parse import quote
from ..core.models import Finding

SENSITIVE_TABLE_WORDS = {
    "users", "profiles", "accounts", "wallets", "payments", "orders",
    "withdrawals", "transactions", "sessions", "admins", "admin_users",
    "api_keys", "secrets", "passwords",
}

def _headers(anon_key="", token=""):
    h = {"Accept": "application/json"}
    if anon_key:
        h["apikey"] = anon_key
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h

def _json(response):
    try:
        return response.json()
    except Exception:
        return None

def audit(client, reporter, anon_key="", access_token=""):
    base = client.base_url.rstrip("/")
    if not base.endswith(".supabase.co"):
        reporter.info("Supabase audit: target does not look like a standard *.supabase.co URL; continuing.")
    # PostgREST root exposes an OpenAPI description when enabled.
    try:
        r = client.request("GET", "/rest/v1/", headers=_headers(anon_key), allow_redirects=False)
    except Exception as exc:
        reporter.error(f"Supabase REST root failed: {exc}")
        return
    reporter.info(f"Supabase REST root: {r.status_code}")
    if r.status_code == 200:
        spec = _json(r)
        if isinstance(spec, dict):
            paths = spec.get("paths", {})
            if paths:
                reporter.info(f"PostgREST published {len(paths)} resource paths.")
            for path, detail in paths.items():
                name = path.strip("/").split("/")[0].lower()
                if name in SENSITIVE_TABLE_WORDS:
                    try:
                        probe = client.request(
                            "GET", f"/rest/v1/{quote(name)}",
                            params={"select": "*", "limit": "1"},
                            headers=_headers(anon_key),
                        )
                    except Exception:
                        continue
                    if probe.status_code == 200 and probe.text.strip() not in ("[]", ""):
                        reporter.add(Finding(
                            "HIGH", "supabase", f"Sensitive table appears anonymously readable: {name}",
                            f"Anonymous REST GET returned HTTP 200 and non-empty data.",
                            "Review RLS policies and ensure sensitive tables are not readable by anon.",
                            probe.url,
                        ))
                    elif probe.status_code == 200:
                        reporter.info(f"Anonymous read allowed but empty: {name}")
        else:
            reporter.info("REST root did not return a JSON OpenAPI document.")
    elif r.status_code in {401, 403}:
        reporter.info("REST root is not anonymously accessible.")
    # Auth and storage reachability are expected in many projects; this is informational.
    for path in ("/auth/v1/settings", "/storage/v1/bucket"):
        try:
            rr = client.request("GET", path, headers=_headers(anon_key))
            reporter.info(f"Supabase endpoint {path}: {rr.status_code}")
        except Exception as exc:
            reporter.info(f"{path}: {exc}")

def rls_read_only(client, reporter, anon_key, token_a, token_b, table, user_column, user_a, user_b):
    path = f"/rest/v1/{table}"
    base = {"select": "*", "limit": "5", user_column: f"eq.{user_b}"}
    headers_a = _headers(anon_key, token_a)
    headers_b = _headers(anon_key, token_b)
    for label, headers in (("A reading B", headers_a), ("B reading B", headers_b)):
        try:
            r = client.request("GET", path, params=base, headers=headers)
        except Exception as exc:
            reporter.error(f"{label}: {exc}")
            continue
        if label.startswith("A") and r.status_code == 200:
            data = _json(r)
            if isinstance(data, list) and data:
                reporter.add(Finding(
                    "HIGH", "rls", f"Cross-user read may be possible on {table}",
                    f"User A received {len(data)} row(s) filtered to user B.",
                    "Review SELECT RLS policy; normally use auth.uid() = owner column or an equivalent server-side authorization rule.",
                    r.url,
                ))
            else:
                reporter.info("A→B read returned no rows.")
        else:
            reporter.info(f"{label}: HTTP {r.status_code}")
    # Also test anonymous read of B's rows, if anon key is available.
    if anon_key:
        try:
            r = client.request("GET", path, params=base, headers=_headers(anon_key))
            if r.status_code == 200 and isinstance(_json(r), list) and _json(r):
                reporter.add(Finding(
                    "HIGH", "rls", f"Anonymous cross-user read on {table}",
                    f"Anonymous request returned rows for {user_b}.",
                    "Enable RLS and require an ownership policy for SELECT.",
                    r.url,
                ))
        except Exception as exc:
            reporter.info(f"Anonymous RLS probe failed: {exc}")
