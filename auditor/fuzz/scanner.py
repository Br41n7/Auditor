from concurrent.futures import ThreadPoolExecutor
from ..core.models import Finding
from ..recon.discovery import derive_words

# This is the one list left that can't come from crawling: these are
# artifacts an attacker guesses precisely *because* they're never
# linked from anywhere on the site (a stray .env, a forgotten backup,
# an exposed .git directory). No amount of spidering finds an unlinked
# file -- that's what makes it worth checking for.
SENSITIVE_ARTIFACTS = {".env", ".git/HEAD", "backup"}

# Only used if you opt in with --seed-common-words, for a target where
# the crawl found little to derive real words from (e.g. a near-empty
# landing page in front of a large private API).
FALLBACK_GENERIC_WORDS = [
    "admin", "administrator", "debug", "test", "dev", "staging",
    "internal", "metrics", "status", "graphql", "storage",
]

def _check_word(client, reporter, prefix, word):
    path = f"{prefix.rstrip('/')}/{word}" if prefix else f"/{word}"
    try:
        r = client.request("GET", path, allow_redirects=False)
    except Exception as exc:
        reporter.info(f"fuzz {path}: {exc}")
        return
    if r.status_code in {200, 206}:
        title = f"Potentially exposed resource: {path}"
        severity = "MEDIUM" if word in SENSITIVE_ARTIFACTS else "INFO"
        if severity != "INFO":
            reporter.add(Finding(
                severity, "fuzzing", title,
                f"GET returned {r.status_code} with {len(r.content)} bytes",
                "Verify this resource is intentionally public; remove or restrict sensitive artifacts.",
                r.url,
            ))
        else:
            reporter.info(f"{r.status_code:3} {path} ({len(r.content)} bytes)")
    elif r.status_code in {401, 403}:
        reporter.info(f"{r.status_code:3} protected {path}")

def build_wordlist(client, include_generic=False, max_items=50):
    """Sensitive-artifact safety net, plus real words seen in the target's
    own URLs/scripts (so guesses like 'orders' or 'vote' are tailored to
    this app instead of a one-size-fits-all list), plus the opt-in
    generic list if requested.
    """
    words = list(SENSITIVE_ARTIFACTS) + derive_words(client)
    if include_generic:
        words += FALLBACK_GENERIC_WORDS
    return list(dict.fromkeys(words))[:max_items]

def path_fuzz(client, reporter, prefix="", words=None, max_items=50, concurrency=1):
    words = (words if words is not None else build_wordlist(client))[:max_items]
    if concurrency <= 1:
        for word in words:
            _check_word(client, reporter, prefix, word)
        return
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(lambda w: _check_word(client, reporter, prefix, w), words))
