from urllib.parse import urlparse
from ..core.models import Finding
from ..recon.discovery import candidate_paths

_FALLBACK_PROTECTED_PATHS = ["/api/me", "/api/profile", "/api/orders", "/api/admin"]
_PROTECTED_KEYWORDS = ("me", "profile", "account", "order", "admin", "dashboard", "user")
_FALLBACK_METHOD_PATHS = ["/", "/api", "/api/profile"]

def auth_probe(client, reporter, token=""):
    if not token:
        reporter.info("Auth checks skipped: no authorized token supplied.")
        return
    protected_paths = candidate_paths(client, _PROTECTED_KEYWORDS, _FALLBACK_PROTECTED_PATHS)
    headers = {"Authorization": f"Bearer {token}"}
    for path in protected_paths:
        try:
            r = client.request("GET", path, headers=headers, allow_redirects=False)
        except Exception as exc:
            reporter.info(f"auth {path}: {exc}")
            continue
        if r.status_code == 200 and path.endswith("admin"):
            reporter.add(Finding(
                "MEDIUM", "authorization", "Admin endpoint accepts supplied user token",
                f"GET {path} returned HTTP 200 for the supplied token.",
                "Verify server-side role/permission enforcement for administrative routes.", r.url))


def cors_probe(client, reporter):
    origin = "https://auditor.invalid"
    try:
        r = client.request("OPTIONS", "/", headers={"Origin": origin, "Access-Control-Request-Method": "GET"})
    except Exception as exc:
        reporter.info(f"CORS probe failed: {exc}")
        return
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao == "*" and acac == "true":
        reporter.add(Finding(
            "HIGH", "cors", "Wildcard CORS with credentials observed",
            "The response allows Origin * while allowing credentials.",
            "Do not combine wildcard origins with credentialed cross-origin requests; allowlist trusted origins.", r.url))
    elif acao == origin and acac == "true":
        reporter.add(Finding(
            "MEDIUM", "cors", "Arbitrary Origin appears reflected with credentials",
            f"The supplied untrusted Origin was reflected with credentials enabled.",
            "Use an explicit trusted-origin allowlist and reject arbitrary Origin values.", r.url))


def method_probe(client, reporter):
    paths = list(dict.fromkeys(["/"] + candidate_paths(client, ("api",), _FALLBACK_METHOD_PATHS)))
    for path in paths:
        try:
            r = client.request("OPTIONS", path)
        except Exception:
            continue
        allow = r.headers.get("Allow", "")
        dangerous = {m.strip().upper() for m in allow.split(",")} & {"PUT", "PATCH", "DELETE"}
        if dangerous:
            reporter.info(f"{path}: advertised methods {', '.join(sorted(dangerous))}")


def host_header_probe(client, reporter):
    parsed = urlparse(client.base_url)
    if not parsed.hostname:
        return
    try:
        r = client.request("GET", "/", headers={"Host": "invalid-auditor-host.invalid"}, allow_redirects=False)
    except Exception:
        return
    location = r.headers.get("Location", "")
    if location and "invalid-auditor-host.invalid" in location:
        reporter.add(Finding(
            "MEDIUM", "host-header", "Host header influences redirect",
            "A deliberately invalid Host value appeared in the Location header.",
            "Build absolute URLs from trusted configuration rather than an unvalidated Host header.", r.url))

def header_security(client, reporter):
    try:
        r = client.request("GET", "/", allow_redirects=False)
    except Exception as exc:
        reporter.info(f"header check failed: {exc}")
        return
    headers = {k.lower(): v for k, v in r.headers.items()}
    if client.base_url.startswith("https://") and "strict-transport-security" not in headers:
        reporter.add(Finding("LOW", "headers", "HSTS header not observed", "Strict-Transport-Security was absent from the root response.", "Enable HSTS after confirming HTTPS is enforced site-wide.", r.url, "medium", "WEB-HEADERS-HSTS"))
    for name, rec in (("content-security-policy", "Consider a restrictive Content-Security-Policy appropriate to the application."), ("x-content-type-options", "Set X-Content-Type-Options: nosniff."), ("referrer-policy", "Set an explicit Referrer-Policy appropriate to the application.")):
        if name not in headers:
            reporter.add(Finding("INFO", "headers", f"{name} header not observed", f"Header {name} was absent from the root response.", rec, r.url, "medium", "WEB-HEADERS-" + name.upper().replace("-", "_")))
