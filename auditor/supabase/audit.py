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

def _extract_owner_value(row, dotted_path):
    """Walk a (possibly PostgREST-embedded) row by a dotted path, e.g.
    'user_id' for a direct column or 'orders.user_id' for a value nested
    under an embedded many-to-one resource.
    """
    cur = row
    for part in dotted_path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur

def probe_cross_user_read(client, reporter, table, path, base_params, anon_key, token_a, token_b, owner_path=None, expected_owner_value=None):
    """Shared cross-user read probe: does token A's request, filtered to
    user B's rows, return anything? Does token B's own request (the
    control) work as expected? Optionally, can an anonymous request read
    user B's rows at all?

    `base_params` must already contain whatever filter (direct column or
    embedded-resource dot-filter) selects "rows belonging to user B" --
    see supabase/planner.py for how chain-based candidates build that
    filter. This is the one place that shape of probe actually runs, so
    both the single-table `rls` command and the full-schema sweep stay
    in sync.

    If `owner_path`/`expected_owner_value` are given, a non-empty response
    is only reported as a finding once at least one returned row is
    verified to actually carry that owner value -- a server that ignores
    the filter entirely and just returns the caller's own default rows
    (not an RLS bug) would otherwise look identical to a real leak.
    """
    headers_a = _headers(anon_key, token_a)
    headers_b = _headers(anon_key, token_b)
    for label, headers in (("A reading B", headers_a), ("B reading B", headers_b)):
        try:
            r = client.request("GET", path, params=base_params, headers=headers)
        except Exception as exc:
            reporter.error(f"{label} ({table}): {exc}")
            continue
        if label.startswith("A") and r.status_code == 200:
            data = _json(r)
            rows = data if isinstance(data, list) else []
            if owner_path and expected_owner_value is not None:
                verified = [row for row in rows if str(_extract_owner_value(row, owner_path)) == str(expected_owner_value)]
            else:
                verified = rows
            if verified:
                reporter.add(Finding(
                    "HIGH", "rls", f"Cross-user read may be possible on {table}",
                    f"User A received {len(verified)} row(s) verified as belonging to user B" + (f" (of {len(rows)} row(s) returned)" if len(rows) != len(verified) else "") + ".",
                    "Review SELECT RLS policy; normally use auth.uid() = owner column (directly, or via an embedded-resource policy for indirect ownership) or an equivalent server-side authorization rule.",
                    r.url,
                ))
            elif rows:
                reporter.info(f"{table}: A's filtered request returned {len(rows)} row(s), but none verified as belonging to user B -- the server may be ignoring the filter and returning its own default set rather than leaking; inspect manually.")
            else:
                reporter.info(f"{table}: A→B read returned no rows.")
        else:
            reporter.info(f"{table}: {label}: HTTP {r.status_code}")
    # Also test anonymous read of B's rows, if anon key is available.
    if anon_key:
        try:
            r = client.request("GET", path, params=base_params, headers=_headers(anon_key))
            data = _json(r)
            rows = data if isinstance(data, list) else []
            if owner_path and expected_owner_value is not None:
                verified = [row for row in rows if str(_extract_owner_value(row, owner_path)) == str(expected_owner_value)]
            else:
                verified = rows
            if r.status_code == 200 and verified:
                reporter.add(Finding(
                    "HIGH", "rls", f"Anonymous cross-user read on {table}",
                    "Anonymous request returned row(s) verified as belonging to the targeted user.",
                    "Enable RLS and require an ownership policy for SELECT.",
                    r.url,
                ))
        except Exception as exc:
            reporter.info(f"Anonymous RLS probe failed ({table}): {exc}")

def rls_read_only(client, reporter, anon_key, token_a, token_b, table, user_column, user_a, user_b):
    path = f"/rest/v1/{table}"
    base = {"select": "*", "limit": "5", user_column: f"eq.{user_b}"}
    probe_cross_user_read(client, reporter, table, path, base, anon_key, token_a, token_b, owner_path=user_column, expected_owner_value=user_b)
