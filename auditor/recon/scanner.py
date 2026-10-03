from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from ..core.models import Finding

# Opt-in only (via --seed-common-paths): a generic baseline for targets
# where crawling turns up little or nothing to check -- e.g. a pure JSON
# API with no linked HTML/JS for the crawler to follow. The default path
# list now comes from actually crawling *your* project (see crawler.py),
# not from this static guess.
FALLBACK_COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/api", "/api/health", "/api/healthz", "/health", "/healthz",
    "/openapi.json", "/swagger.json", "/docs",
    "/api/auth", "/api/login", "/api/register", "/api/me",
    "/api/users", "/api/profile", "/api/orders", "/api/products",
    "/api/admin", "/api/admin/users", "/api/admin/orders",
    "/api/paystack", "/api/paystack/verify",
    "/api/webhooks", "/api/upload", "/api/uploads",
]

def _check_path(client, reporter, path):
    try:
        r = client.request("GET", path)
    except Exception as exc:
        reporter.info(f"{path}: request failed: {exc}")
        return
    if r.status_code in {200, 204}:
        reporter.info(f"{r.status_code:3} GET {path}")
    elif r.status_code not in {404, 405}:
        reporter.info(f"{r.status_code:3} GET {path}")

def endpoint_scan(client, reporter, paths, concurrency=1):
    """Check a list of paths for interesting status codes. `paths` is
    normally what the crawler discovered on the actual target (plus the
    opt-in fallback list, if requested) -- see cli.py.
    """
    paths = list(dict.fromkeys(paths))
    if not paths:
        reporter.info("No paths to check: the crawl found nothing here. "
                       "Pass --seed-common-paths for a generic baseline list.")
        return
    if concurrency <= 1:
        for path in paths:
            _check_path(client, reporter, path)
        return
    # The client's own rate limiter still gates actual request timing;
    # the pool just keeps waiting threads from sitting idle in series.
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(lambda p: _check_path(client, reporter, p), paths))

def header_scan(client, reporter):
    try:
        r = client.request("GET", "/")
    except Exception as exc:
        reporter.error(f"Target unavailable: {exc}")
        return
    expected = {
        "strict-transport-security": "HTTPS transport policy",
        "content-security-policy": "browser script/resource policy",
        "x-content-type-options": "MIME sniffing protection",
        "referrer-policy": "referrer leakage policy",
        "permissions-policy": "browser feature policy",
    }
    for header, purpose in expected.items():
        if header not in {h.lower() for h in r.headers}:
            reporter.add(Finding(
                "LOW", "headers", f"Missing {header}",
                f"GET / returned {r.status_code} without {header}",
                f"Consider adding {header} ({purpose})",
                r.url,
            ))
    if r.url.startswith("https://") and "strict-transport-security" not in {h.lower() for h in r.headers}:
        reporter.add(Finding(
            "LOW", "headers", "HSTS not observed",
            "HTTPS target did not return Strict-Transport-Security",
            "Enable HSTS after confirming HTTPS is used consistently.",
            r.url,
        ))
    reporter.info(f"Headers checked: {r.url} ({r.status_code})")

def discovery(client, reporter):
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        try:
            r = client.request("GET", path)
        except Exception:
            continue
        if r.status_code == 200 and r.text:
            reporter.info(f"Discovery resource: {path} ({len(r.text)} bytes)")
