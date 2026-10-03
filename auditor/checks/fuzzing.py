from ..core.models import Finding

PAYLOADS = [
    "'", '"', "<script>alert(1)</script>", "..%2f..%2f", "%27%20OR%201%3D1--",
]

def reflected_input(client, reporter, path="/"):
    for payload in PAYLOADS:
        try:
            r = client.request("GET", path, params={"q": payload}, allow_redirects=False)
        except Exception as exc:
            reporter.info(f"input fuzz failed: {exc}")
            continue
        if payload in r.text:
            reporter.add(Finding(
                "LOW", "fuzzing", "User-controlled query value reflected in response",
                f"The q parameter value was reflected for payload {payload!r}.",
                "Encode untrusted output for its HTML/JS context and validate input. Reflection alone is not proof of XSS.", r.url))


def api_error_fuzz(client, reporter, paths):
    for path in paths:
        for payload in ("-1", "0", "999999999", "null"):
            try:
                r = client.request("GET", path, params={"id": payload}, allow_redirects=False)
            except Exception:
                continue
            if r.status_code >= 500:
                reporter.add(Finding(
                    "MEDIUM", "fuzzing", "Server error triggered by simple parameter fuzz",
                    f"GET {path}?id={payload} returned HTTP {r.status_code}.",
                    "Review server-side validation and error handling; avoid exposing stack traces or database errors.", r.url))
