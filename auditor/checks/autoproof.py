"""Controlled automatic proof-of-impact checks.

This module intentionally supports only non-destructive verification. It can
reproduce read-only authorization findings when all required values are
provided, but it will not create orders, alter prices, issue refunds,
withdraw funds, execute arbitrary commands, or replay payment mutations.
"""
from ..core.models import Finding
from .authz import idor_probe


def prove_idor(client, reporter, path, id_a, id_b, token_a, token_b):
    """Automatically reproduce a suspected BOLA/IDOR using GET only."""
    if not all((path, id_a, id_b, token_a, token_b)):
        raise ValueError("IDOR proof requires path, id-a, id-b, token-a and token-b")
    idor_probe(client, reporter, path, id_a, id_b, token_a, token_b)


def prove_cross_user(client, reporter, path, id_a, id_b, token_a, token_b):
    """Explicit read-only cross-user proof with a stronger evidence record."""
    if "{id}" not in path:
        raise ValueError("--path must contain an {id} placeholder")
    a_own = path.replace("{id}", str(id_a))
    b_obj = path.replace("{id}", str(id_b))
    import requests
    try:
        own = client.request("GET", a_own, headers={"Authorization": f"Bearer {token_a}"}, allow_redirects=False)
        cross = client.request("GET", b_obj, headers={"Authorization": f"Bearer {token_a}"}, allow_redirects=False)
        b_own = client.request("GET", b_obj, headers={"Authorization": f"Bearer {token_b}"}, allow_redirects=False)
    except requests.RequestException as exc:
        reporter.error(f"Automatic proof failed: {exc}")
        return
    reporter.info(f"Proof matrix: A-own={own.status_code}, A-cross={cross.status_code}, B-own={b_own.status_code}")
    if own.status_code == 200 and b_own.status_code == 200 and cross.status_code == 200:
        reporter.add(Finding(
            "HIGH", "authorization", "Reproduced cross-user object access",
            f"Account A can read its own object ({own.status_code}) and account B's object ({cross.status_code}); account B can read its own object ({b_own.status_code}).",
            "Enforce object-level authorization using the authenticated principal before returning the object.",
            client.url(b_obj), confidence="high", check_id="autoproof.bola-read"))
    elif cross.status_code in (401, 403, 404):
        reporter.info("Automatic proof did not reproduce cross-user access; access was denied.")
    else:
        reporter.info("Automatic proof is inconclusive; review the response and application authorization semantics.")
