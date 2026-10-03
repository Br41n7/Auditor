"""Shared helper so each check can ask "what did the crawl actually find
that looks relevant to me?" instead of hardcoding its own guess list.

A check still has a fallback constant for when nothing was crawled (a
pure JSON API with no HTML/JS to spider, or --no-crawl was passed) --
but that fallback is now the exception path, not the default behavior.
"""


def candidate_paths(client, keywords, fallback):
    """Same-origin paths the crawl discovered that contain any of
    `keywords`. Falls back to the caller's static list only if the crawl
    found nothing matching (or nothing at all).
    """
    site = getattr(client, "discovered", None)
    if not site:
        return list(fallback)
    hits = [p for p in site.all_paths() if any(k in p.lower() for k in keywords)]
    return hits or list(fallback)


def candidate_params(client, keywords, fallback):
    """Real parameter names (from forms, links, and JS) the crawl saw
    that match any of `keywords`. Falls back to the caller's static set
    if the crawl found no parameters at all, or none matching.
    """
    site = getattr(client, "discovered", None)
    if not site or not site.params:
        return set(fallback)
    hits = {p for p in site.params if any(k in p.lower() for k in keywords)}
    return hits or set(fallback)


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
