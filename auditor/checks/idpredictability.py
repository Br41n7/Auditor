"""Object-identifier predictability signal.

Entirely crawl-derived -- there is nothing to hardcode here. The crawler
already sees real path segments while it walks the site (e.g. the "482"
in /api/orders/482, or a UUID in /api/tickets/3fae...); this check just
looks at the shape of those segments. A small sequential/numeric ID is
a much stronger IDOR-enumeration enabler than an opaque UUID, because
once one valid ID is known an attacker can simply count: 481, 480, 483...
This doesn't attempt to enumerate anything itself -- it only reports the
shape of what the crawl already saw.
"""
import re
from ..core.models import Finding

NUMERIC_ID_RE = re.compile(r"^\d{1,10}$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
OPAQUE_HEX_RE = re.compile(r"^[0-9a-fA-F]{20,}$")
STATIC_SEGMENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_-]*$")  # looks like a route name, not an id


def _classify_segments(paths):
    numeric_examples = {}
    opaque_count = 0
    for path in paths:
        for segment in path.strip("/").split("/"):
            if not segment:
                continue
            if NUMERIC_ID_RE.match(segment):
                numeric_examples.setdefault(segment, path)
            elif UUID_RE.match(segment) or OPAQUE_HEX_RE.match(segment):
                opaque_count += 1
    return numeric_examples, opaque_count


def scan(client, reporter):
    site = getattr(client, "discovered", None)
    if not site:
        return
    paths = site.all_paths()
    numeric_examples, opaque_count = _classify_segments(paths)
    if not numeric_examples:
        return
    examples = list(numeric_examples.values())[:3]
    note = ""
    if opaque_count:
        note = f" ({opaque_count} other discovered segment(s) look opaque/UUID-shaped, so ID shape is inconsistent across the app.)"
    reporter.add(Finding(
        "INFO", "authorization", "Object identifiers observed in the crawl appear sequential/numeric",
        f"{len(numeric_examples)} distinct small numeric id(s) seen in discovered paths, e.g. {', '.join(examples)}.{note}",
        "Sequential numeric IDs make IDOR/BOLA enumeration trivial once a single valid ID is known (just count up/down). This is not a vulnerability by itself -- the server-side ownership check is what actually matters -- but it raises the stakes of getting that check wrong, and makes a missed check far easier to find by accident. Where feasible, prefer non-sequential identifiers (UUIDs) for objects reachable by direct ID; either way, verify every one of these endpoints enforces ownership server-side, not just existence.",
        None, confidence="medium", check_id="AUTHZ-ID-PREDICTABILITY",
    ))
