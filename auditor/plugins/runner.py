from dataclasses import dataclass
from typing import Callable
from ..checks import web, auth, files, django, nextjs, payments, business
from ..checks.fuzzing import reflected_input, api_error_fuzz

@dataclass(frozen=True)
class Check:
    id: str
    name: str
    category: str
    profiles: tuple[str, ...]
    run: Callable
    safe: bool = True

REGISTRY = [
    Check("web.headers", "Security headers and CORS", "web", ("generic", "django", "nextjs"), web.header_security, True),
    Check("web.cors", "CORS policy", "web", ("generic", "django", "nextjs"), web.cors_probe, True),
    Check("web.host", "Host header behavior", "web", ("generic", "django", "nextjs"), web.host_header_probe, True),
    Check("auth.metadata", "JWT/OIDC discovery", "auth", ("generic", "django", "nextjs"), auth.jwt_surface, True),
    Check("auth.unauth", "Unauthenticated sensitive paths", "auth", ("generic", "django", "nextjs"), auth.unauthenticated_sensitive_paths, True),
    Check("files.surface", "Upload surface discovery", "files", ("generic", "django", "nextjs"), files.upload_surface, True),
    Check("payments.surface", "Payment endpoint review", "payments", ("generic", "django", "nextjs"), payments.scan, True),
    Check("business.surface", "Business logic surface review", "business-logic", ("generic", "django", "nextjs"), business.scan, True),
    # NOTE: business-flow integrity checks are declarative/spec-driven and
    # can't be auto-run (they need a spec file only you can supply) -- use
    # `auditor flow <spec.json>` directly instead of `app`/`audit`.
    Check("django.surface", "Django exposure checks", "django", ("django",), django.scan, True),
    Check("nextjs.surface", "Next.js exposure checks", "nextjs", ("nextjs",), nextjs.scan, True),
]

CHECKS = {c.id: c for c in REGISTRY}

def list_checks(): return REGISTRY

def run_project_checks(client, reporter, token="", profile="auto", selected=None):
    if profile == "auto": profile = "generic"
    wanted = set(selected or CHECKS)
    for check in REGISTRY:
        if check.id not in wanted or profile not in check.profiles: continue
        try:
            check.run(client, reporter)
        except Exception as exc:
            reporter.info(f"{check.id} failed: {exc}")
