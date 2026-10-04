"""Shared helper so each check can ask "what did the crawl actually find
that looks relevant to me?" instead of hardcoding its own guess list.

A check can still name a fallback constant for when nothing was crawled
(a pure JSON API with no HTML/JS to spider, or --no-crawl was passed) --
but that fallback is the exception path, not the default behavior, and
it's skipped entirely when the client has opted into --strict-crawl
(see cli.py): then a check reports only what the crawl actually found,
even if that's nothing.
"""
import re

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(text):
    """Lowercase alnum tokens from a path/string, split on any non-
    alnum boundary (/, -, _, ., ?, etc.). Used instead of raw substring
    matching so a keyword like 'poll' doesn't false-match inside an
    unrelated word like 'apollo' -- it has to actually be a whole
    path segment (or a simple plural of one), not just a substring.
    """
    return _TOKEN_RE.findall(text.lower())


def _keyword_hits(text, keywords):
    """Keywords actually matched in `text` as whole tokens (or a short
    plural/suffix of one, e.g. 'vote' matching the token 'votes').
    Returns the set of matched keywords, empty if none matched.
    """
    tokens = _tokens(text)
    hits = set()
    for kw in keywords:
        if kw in tokens:
            hits.add(kw)
            continue
        if any(tok.startswith(kw) and len(tok) - len(kw) <= 2 for tok in tokens):
            hits.add(kw)
    return hits


def matches_keywords(text, keywords):
    """Public wrapper: does `text` (a path, a parameter name, anything)
    contain any of `keywords` as a whole token (or short plural/suffix)?
    """
    return bool(_keyword_hits(text, keywords))


def _is_strict(client):
    return bool(getattr(client, "strict_crawl", False))


def candidate_paths(client, keywords, fallback):
    """Same-origin paths the crawl discovered that match any of
    `keywords` as whole path segments. Falls back to the caller's static
    list only if the crawl found nothing matching (or nothing at all),
    and only if --strict-crawl was not requested.
    """
    site = getattr(client, "discovered", None)
    if not site:
        return [] if _is_strict(client) else list(fallback)
    hits = [p for p in site.all_paths() if _keyword_hits(p, keywords)]
    if hits:
        return hits
    return [] if _is_strict(client) else list(fallback)


def candidate_params(client, keywords, fallback):
    """Real parameter names (from forms, links, and JS) the crawl saw
    that match any of `keywords`. Falls back to the caller's static set
    if the crawl found no parameters at all, or none matching -- unless
    --strict-crawl was requested.
    """
    site = getattr(client, "discovered", None)
    if not site or not site.params:
        return set() if _is_strict(client) else set(fallback)
    hits = {p for p in site.params if _keyword_hits(p, keywords)}
    if hits:
        return hits
    return set() if _is_strict(client) else set(fallback)


def derive_words(client, max_words=60):
    """Directory/segment names actually used in the app's own URLs and
    scripts (e.g. 'orders', 'vote', 'ticket' for an event-ticketing app),
    for fuzzing filename/path guesses tailored to this specific target
    rather than a generic list.
    """
    site = getattr(client, "discovered", None)
    if not site:
        return []
    words = set()
    for path in site.all_paths():
        for segment in path.strip("/").split("/"):
            if segment and not segment.isdigit() and len(segment) <= 30:
                words.add(segment)
    return sorted(words)[:max_words]


def keyword_signal_score(client, strong_keywords, supporting_keywords=(), param_keywords=()):
    """How strongly does the crawl's own discovered paths/params suggest
    this target belongs to a particular category (e.g. "voting
    platform")? Used to gate category-specific checks so they only run
    -- and only probe paths actually seen on this target -- when there's
    real evidence, instead of firing generic category checks (and their
    hardcoded guesses) at every target regardless of relevance.

    Scoring: +2 per distinct path matching a strong keyword, +1 per
    distinct path matching a supporting keyword, +1 per discovered
    parameter name matching a param keyword. Purely a function of what
    the crawl found -- no network calls, no guessing.
    """
    site = getattr(client, "discovered", None)
    if not site:
        return 0
    score = 0
    for path in site.all_paths():
        hits = _keyword_hits(path, strong_keywords)
        if hits:
            score += 2
            continue
        if _keyword_hits(path, supporting_keywords):
            score += 1
    if param_keywords:
        for param in site.params:
            if _keyword_hits(param, param_keywords):
                score += 1
    return score
