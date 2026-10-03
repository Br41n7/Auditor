"""Low-impact business-logic surface discovery and integrity review helpers.

These checks deliberately avoid changing server state. They identify places where
manual or explicitly configured authorization/business-flow tests are warranted.
"""
from ..core.models import Finding
from ..recon.discovery import candidate_paths, candidate_params

# Used only if the crawl found nothing business-shaped (e.g. everything
# sits behind auth the crawler never logged into).
_FALLBACK_BUSINESS_PATHS = (
    "/api/cart", "/api/carts", "/api/checkout", "/api/orders", "/api/order",
    "/api/products", "/api/product", "/api/tickets", "/api/ticket",
    "/api/wallet", "/api/wallets", "/api/withdrawals", "/api/refunds",
    "/api/coupons", "/api/discounts", "/api/subscriptions", "/api/payments",
)
_BUSINESS_KEYWORDS = ("cart", "checkout", "order", "product", "ticket", "wallet", "withdraw", "refund", "coupon", "discount", "subscription", "payment")
SENSITIVE_PARAMS = {"price", "amount", "quantity", "qty", "discount", "coupon", "role", "status", "user_id", "seller_id", "owner_id"}


def _json_keys(value, prefix=""):
    keys = set()
    if isinstance(value, dict):
        for k, v in value.items():
            keys.add(str(k).lower())
            keys |= _json_keys(v, prefix + str(k) + ".")
    elif isinstance(value, list):
        for item in value[:5]:
            keys |= _json_keys(item, prefix)
    return keys


def scan(client, reporter):
    """Discover business endpoints (from the crawl, where possible) and client-visible business fields."""
    for path in candidate_paths(client, _BUSINESS_KEYWORDS, _FALLBACK_BUSINESS_PATHS):
        try:
            r = client.request("GET", path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code in {404, 405}:
            continue
        reporter.info(f"Business surface {path}: HTTP {r.status_code}")
        if r.status_code in {200, 206}:
            keys = set()
            try:
                keys = _json_keys(r.json())
            except Exception:
                pass
            hits = sorted(keys & SENSITIVE_PARAMS)
            if hits:
                reporter.add(Finding(
                    "LOW", "business-logic",
                    "Client-visible business control fields require integrity review",
                    f"{path} exposed business-related fields: {', '.join(hits[:12])}.",
                    "Verify on the server that price, amount, quantity, discount, role, ownership, and status are derived or validated server-side; do not trust client-supplied values.",
                    r.url, confidence="medium", check_id="business.client-controls"
                ))


def review_query_surface(client, reporter, path="/api/checkout"):
    """Probe harmless query variants to identify endpoints that accept business parameters.

    Uses parameter names the crawl actually saw on this target (form fields,
    link/script query strings) that match known-sensitive names, falling
    back to a generic probe set if the crawl found none. This does not
    attempt a modified transaction or write operation.
    """
    fallback_probes = ("price=1", "amount=1", "quantity=1", "role=user", "status=paid")
    params = candidate_params(client, SENSITIVE_PARAMS, fallback=())
    probes = [f"{p}=1" for p in sorted(params)] if params else list(fallback_probes)
    for query in probes:
        try:
            r = client.request("GET", f"{path}?{query}", allow_redirects=False)
        except Exception:
            continue
        if r.status_code not in {404, 405}:
            reporter.add(Finding(
                "INFO", "business-logic",
                "Business parameter accepted by a reachable endpoint",
                f"GET {path}?{query} returned HTTP {r.status_code}; this is a review signal, not proof of a vulnerability.",
                "Confirm that the parameter cannot alter server-side price, quantity, role, ownership, payment state, or fulfillment without independent authorization and server-side validation.",
                r.url, confidence="low", check_id="business.query-surface"
            ))
