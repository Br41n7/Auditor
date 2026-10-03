from ..core.models import Finding

def scan(client, reporter):
    for path in ("/admin/", "/__debug__/", "/static/admin/"):
        try:
            r = client.request("GET", path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200 and path == "/__debug__/":
            reporter.add(Finding(
                "HIGH", "django", "Django debug surface appears accessible",
                f"GET {path} returned HTTP 200.",
                "Disable DEBUG and restrict debug tooling outside controlled development environments.", r.url))
        elif r.status_code in {200, 302, 401, 403}:
            reporter.info(f"Django-like path {path}: HTTP {r.status_code}")
