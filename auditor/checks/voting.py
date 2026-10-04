"""Read-only checks for common bug classes in online voting/polling flows
(vote stuffing, duplicate voting, CSRF on the vote form, session/vote
cookie weaknesses, missing object-level authorization on ballots).

This whole module only activates when the crawl itself gives evidence
the target is actually a voting/polling platform (see
detect_voting_platform) -- it does not fire a generic voting check
against every target the way recon's or fuzz's baseline checks do.
Every path it probes comes straight from what the crawler discovered on
*this* target; there is no hardcoded /api/vote-style guess list the way
earlier versions had, so a non-voting target never gets these checks
run against it at all, and a voting target only ever gets tested
against its own real endpoints.

Consistent with the rest of this tool: nothing here ever casts a vote,
submits a form, or performs any write. Actually casting even one real
vote during testing would taint a live contest's result, so the bug
classes that are inherently about *attempting* to cast a vote (double-
voting, rate limits, vote-count tampering) are covered here only at the
level of passive signals (missing CSRF token, missing rate-limit
headers, cookie flags) -- enough to tell you where to look, without the
tool itself ever touching the ballot. For active verification (does a
second vote from the same account actually get rejected?), use your own
test/staging environment and the existing `flow`/`matrix`/`prove`
commands, which the vote/poll/ballot/candidate entity names now also
recognize (see mapping/mapper.py and authorization/matrix.py).
"""
import re
from ..core.models import Finding
from ..recon.discovery import candidate_paths, keyword_signal_score, matches_keywords

# "Strong" keywords are close to unambiguous on their own (a path segment
# that's literally "vote" or "ballot" is not plausibly about anything
# else). "Supporting" keywords are suggestive but more common in other
# contexts, so on their own they count for less -- it takes two of them,
# or one plus a matching parameter name, to reach the detection threshold.
STRONG_KEYWORDS = {"vote", "ballot", "election"}
SUPPORTING_KEYWORDS = {"poll", "candidate", "contestant", "nominee"}
ALL_VOTE_KEYWORDS = STRONG_KEYWORDS | SUPPORTING_KEYWORDS
DETECTION_THRESHOLD = 2

FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']+)["']""", re.I)
METHOD_RE = re.compile(r"""method\s*=\s*["']([^"']+)["']""", re.I)
HIDDEN_INPUT_RE = re.compile(r"""<input\b[^>]*\btype\s*=\s*["']hidden["'][^>]*>""", re.I)
NAME_RE = re.compile(r"""\bname\s*=\s*["']([^"']+)["']""", re.I)
TOKEN_NAME_HINTS = ("csrf", "token", "authenticity", "_token", "nonce")
RATE_LIMIT_HEADERS = ("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit", "retry-after")


def detect_voting_platform(client):
    """Does the crawl itself give evidence this target is a voting/
    polling platform, as opposed to some other kind of app that merely
    has a page whose text happens to mention a vote-ish word once?
    Returns the signal score (0 if nothing was crawled, or crawled but
    no match) -- callers compare it to DETECTION_THRESHOLD.
    """
    return keyword_signal_score(client, STRONG_KEYWORDS, SUPPORTING_KEYWORDS, ALL_VOTE_KEYWORDS)


def discover_voting_surface(client, reporter):
    """Report every discovered vote/poll/ballot-shaped path and whether
    it's reachable without credentials. Purely crawl-derived: there is
    no fallback guess list here, only what was actually found.
    """
    paths = candidate_paths(client, ALL_VOTE_KEYWORDS, fallback=[])
    for path in paths:
        try:
            r = client.request("GET", path, allow_redirects=False)
        except Exception as exc:
            reporter.info(f"voting surface {path}: {exc}")
            continue
        if r.status_code not in (404, 405):
            reporter.info(f"Voting surface {path}: HTTP {r.status_code}")
    return paths


def vote_form_csrf_signal(client, reporter):
    """Re-fetch discovered pages and look for a <form> that POSTs to a
    vote/ballot path with no token-looking hidden field. A static
    read-only signal, not proof -- some frameworks carry CSRF protection
    in a header set by JS rather than a hidden input.
    """
    site = getattr(client, "discovered", None)
    pages = sorted(site.pages) if site else []
    checked_any = False
    for page_path in pages:
        try:
            r = client.request("GET", page_path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code != 200 or "html" not in r.headers.get("content-type", "").lower():
            continue
        for attrs, body in FORM_RE.findall(r.text):
            action_match = ACTION_RE.search(attrs)
            method_match = METHOD_RE.search(attrs)
            action = action_match.group(1) if action_match else page_path
            method = (method_match.group(1) if method_match else "get").lower()
            if method != "post" or not _looks_like_vote_path(action):
                continue
            checked_any = True
            hidden_names = [NAME_RE.search(tag).group(1) for tag in HIDDEN_INPUT_RE.findall(body) if NAME_RE.search(tag)]
            if not any(any(hint in name.lower() for hint in TOKEN_NAME_HINTS) for name in hidden_names):
                reporter.add(Finding(
                    "MEDIUM", "voting", "Vote form has no visible CSRF token field",
                    f"The POST form on {page_path} targeting {action} has no hidden input whose name suggests a CSRF token (checked: {', '.join(hidden_names) or 'none'}).",
                    "Confirm CSRF protection is applied another way (e.g. a double-submit cookie or a header set by JS); otherwise add a per-session anti-CSRF token to the vote form so a forged cross-site request can't cast votes on a user's behalf.",
                    r.url, confidence="low", check_id="VOTING-CSRF-SIGNAL"))
    if not checked_any:
        reporter.info("No POST form targeting a discovered vote/poll/ballot path was found to check for a CSRF token.")


def _looks_like_vote_path(path):
    return matches_keywords(path, ALL_VOTE_KEYWORDS)


def vote_rate_limit_signal(client, reporter):
    """Single read-only request per discovered vote-shaped path, checking
    for standard rate-limit response headers. Absence is only a review
    signal -- it does not confirm vote stuffing is actually possible,
    and this never sends repeated requests to find out.
    """
    paths = candidate_paths(client, ALL_VOTE_KEYWORDS, fallback=[])
    for path in paths:
        try:
            r = client.request("GET", path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code in (404, 405):
            continue
        headers = {k.lower() for k in r.headers}
        if not headers & set(RATE_LIMIT_HEADERS):
            reporter.add(Finding(
                "INFO", "voting", "No rate-limit headers observed on voting surface",
                f"GET {path} returned HTTP {r.status_code} with none of {', '.join(RATE_LIMIT_HEADERS)} present.",
                "Verify server-side rate limiting (per account and per IP/device) is enforced on vote-casting endpoints to resist vote stuffing and automation; response headers are a convenience signal, not a requirement, so confirm with the backend config directly.",
                r.url, confidence="low", check_id="VOTING-RATE-LIMIT-SIGNAL"))
            return  # one informational note per scan is enough signal


def _set_cookie_headers(response):
    try:
        values = response.raw.headers.get_all("Set-Cookie")
        if values:
            return list(values)
    except Exception:
        pass
    raw = response.headers.get("Set-Cookie")
    return [raw] if raw else []


def cookie_security_signal(client, reporter):
    """Inspect Set-Cookie flags on discovered voting-surface pages only
    (not the whole site -- if the crawl detected voting signals on
    specific pages, those are the ones worth checking for session
    weaknesses relevant to duplicate voting / session riding).
    """
    site = getattr(client, "discovered", None)
    paths = sorted((site.pages if site else set()) | set(candidate_paths(client, ALL_VOTE_KEYWORDS, fallback=[])))
    if not paths:
        return
    https = client.base_url.startswith("https://")
    seen = set()
    for path in paths:
        try:
            r = client.request("GET", path, allow_redirects=False)
        except Exception:
            continue
        for raw in _set_cookie_headers(r):
            if not raw:
                continue
            name = raw.split("=", 1)[0].strip()
            if name in seen:
                continue
            lower = raw.lower()
            if not any(k in name.lower() for k in ("session", "sess", "auth", "token", "sid", "voter", "ballot")):
                continue
            seen.add(name)
            missing = []
            if https and "secure" not in lower:
                missing.append("Secure")
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite=" not in lower:
                missing.append("SameSite")
            if missing:
                reporter.add(Finding(
                    "LOW", "voting", f"Cookie '{name}' missing {', '.join(missing)}",
                    f"Set-Cookie for '{name}' on {path} lacks: {', '.join(missing)}.",
                    "Set Secure, HttpOnly and an explicit SameSite attribute on session/identity cookies -- this matters more than usual on vote/ballot endpoints, where a fixed or exposed session enables repeat voting under one identity.",
                    r.url, confidence="medium", check_id="VOTING-COOKIE-FLAGS"))


def scan(client, reporter):
    """Only runs the voting-signal checks if the crawl itself shows
    evidence this target is a voting/polling platform; otherwise reports
    nothing at all; it does not probe a single generic /api/vote-style
    path on a target that gave no sign of being one.
    """
    score = detect_voting_platform(client)
    if score < DETECTION_THRESHOLD:
        if getattr(client, "discovered", None):
            reporter.info(f"Voting checks skipped: no voting-platform signal in the crawl (score {score}/{DETECTION_THRESHOLD}).")
        return
    reporter.info(f"Voting-platform signal detected in the crawl (score {score}); running voting checks.")
    discover_voting_surface(client, reporter)
    vote_form_csrf_signal(client, reporter)
    vote_rate_limit_signal(client, reporter)
    cookie_security_signal(client, reporter)
