from ..core.models import Finding

def scan(client, reporter):
    for path in ("/_next/", "/_next/static/", "/api/health"):
        try:
            r = client.request("GET", path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200:
            reporter.info(f"Next.js-like surface {path}: HTTP 200")
