from ..core.models import Finding
from ..recon.discovery import candidate_paths

_FALLBACK_UPLOAD_PATHS = ("/api/upload", "/api/uploads", "/upload", "/uploads")
_UPLOAD_KEYWORDS = ("upload", "file", "media", "asset", "attachment", "avatar", "image")

def upload_surface(client, reporter):
    paths = candidate_paths(client, _UPLOAD_KEYWORDS, _FALLBACK_UPLOAD_PATHS)
    for path in paths:
        try:
            r = client.request("GET", path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code in {200, 401, 403, 405}:
            reporter.info(f"Upload surface {path}: HTTP {r.status_code}")
            if r.status_code == 200 and "text/html" in r.headers.get("Content-Type", "").lower():
                reporter.add(Finding(
                    "INFO", "upload", "Potential upload surface discovered",
                    f"GET {path} returned an HTML response.",
                    "Review server-side file type validation, filename handling, storage isolation, and execution controls.", r.url))
