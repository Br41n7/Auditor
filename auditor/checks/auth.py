from ..core.models import Finding
from ..recon.discovery import candidate_paths

_FALLBACK_SENSITIVE_PATHS = ("/api/me", "/api/profile", "/api/orders", "/api/wallet", "/api/admin/users")
_SENSITIVE_KEYWORDS = ("me", "profile", "account", "order", "wallet", "admin", "user", "dashboard")

def jwt_surface(client, reporter):
    for path in ("/.well-known/jwks.json", "/.well-known/openid-configuration"):
        try:
            r = client.request("GET", path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200:
            reporter.info(f"Auth metadata discovered: {path}")

def unauthenticated_sensitive_paths(client, reporter):
    for path in candidate_paths(client, _SENSITIVE_KEYWORDS, _FALLBACK_SENSITIVE_PATHS):
        try:
            r = client.request("GET", path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200:
            reporter.add(Finding(
                "MEDIUM", "authentication", "Potentially sensitive endpoint accessible without supplied credentials",
                f"Unauthenticated GET {path} returned HTTP 200.",
                "Confirm whether this resource is intentionally public; otherwise require authentication and authorization.", r.url))
