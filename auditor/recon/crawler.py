"""Attacker-style same-origin recon: instead of guessing paths from a
static wordlist, actually crawl the target the way a human attacker
doing recon would -- follow links, read robots.txt/sitemap.xml, pull
routes out of bundled JS, and collect the parameter names the app
itself uses in forms, links and scripts.

Everything here is read-only (GET only, no form submission, no script
execution) and stays same-origin.
"""
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs

HTML_ATTR_RE = re.compile(r'''(?:href|src|action)\s*=\s*["']([^"'#>\s]+)["']''', re.I)
INPUT_NAME_RE = re.compile(r'''<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']''', re.I)
JS_PATH_LITERAL_RE = re.compile(r'''["'](/[A-Za-z0-9_][A-Za-z0-9_\-./]{1,120})["']''')
SITEMAP_LOC_RE = re.compile(r'<loc>\s*([^<\s]+)\s*</loc>', re.I)
ROBOTS_DISALLOW_RE = re.compile(r'^\s*Disallow:\s*(\S+)', re.I | re.M)

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm", ".pdf",
    ".zip",
}

DEFAULT_SEEDS = ("/", "/robots.txt", "/sitemap.xml")


@dataclass
class SiteMap:
    """What the crawl learned about the target: real pages, real scripts,
    and real parameter names -- everything the later checks need instead
    of a canned guess list.
    """
    pages: set = field(default_factory=set)
    js_files: set = field(default_factory=set)
    params: set = field(default_factory=set)
    fetched: int = 0

    def all_paths(self):
        return sorted(self.pages | self.js_files)


def _normalize(base_url, link):
    """Resolve a possibly-relative link against base_url. Returns the
    same-origin path, or None if it's off-origin, not http(s), or points
    at a static asset we have no reason to probe as an "endpoint".
    """
    if not link or link.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
        return None
    resolved = urljoin(base_url, link)
    b, r = urlparse(base_url), urlparse(resolved)
    if r.scheme not in ("http", "https") or (b.scheme, b.netloc) != (r.scheme, r.netloc):
        return None
    path = r.path or "/"
    if any(path.lower().endswith(ext) for ext in STATIC_EXTENSIONS):
        return None
    return path, r.query


def _harvest(base_url, path, response):
    """Pull links, script paths, form/query parameter names, and (for
    robots.txt/sitemap.xml) extra seed paths out of one fetched response.
    """
    links, js_files, params, extra_seeds = set(), set(), set(), set()
    content_type = response.headers.get("content-type", "").lower()
    text = response.text if response.status_code == 200 else ""

    if path == "/sitemap.xml" and text:
        for loc in SITEMAP_LOC_RE.findall(text):
            norm = _normalize(base_url, loc)
            if norm:
                extra_seeds.add(norm[0])

    if path == "/robots.txt" and text:
        # An attacker reads Disallow lines as a map of "things the owner
        # didn't want indexed" -- often admin panels or internal tooling.
        for entry in ROBOTS_DISALLOW_RE.findall(text):
            norm = _normalize(base_url, entry)
            if norm:
                extra_seeds.add(norm[0])

    if "html" in content_type and text:
        for match in HTML_ATTR_RE.finditer(text):
            norm = _normalize(base_url, match.group(1))
            if not norm:
                continue
            found_path, query = norm
            if query:
                params.update(parse_qs(query).keys())
            (js_files if found_path.endswith(".js") else links).add(found_path)
        for name in INPUT_NAME_RE.finditer(text):
            params.add(name.group(1))

    if path.endswith(".js") or "javascript" in content_type:
        for match in JS_PATH_LITERAL_RE.finditer(text):
            norm = _normalize(base_url, match.group(1))
            if norm:
                links.add(norm[0])

    if response.url:
        query = urlparse(response.url).query
        if query:
            params.update(parse_qs(query).keys())

    return links, js_files, params, extra_seeds


def _fetch_many(client, paths, concurrency):
    def _one(path):
        try:
            return path, client.request("GET", path, allow_redirects=False), None
        except Exception as exc:
            return path, None, exc

    if concurrency <= 1 or len(paths) <= 1:
        return [_one(p) for p in paths]
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        return list(pool.map(_one, paths))


def crawl(client, reporter, seeds=None, max_pages=60, max_depth=3, concurrency=1):
    """Breadth-first, same-origin crawl of the target.

    Returns a SiteMap of what was actually found on the app itself --
    the basis every check should probe against, in place of a static
    hardcoded path/parameter list.
    """
    seeds = list(dict.fromkeys(seeds or DEFAULT_SEEDS))
    site = SiteMap()
    visited = set()
    frontier = seeds
    depth = 0
    while frontier and site.fetched < max_pages and depth <= max_depth:
        frontier = [p for p in dict.fromkeys(frontier) if p not in visited]
        if not frontier:
            break
        frontier = frontier[: max_pages - site.fetched]
        results = _fetch_many(client, frontier, concurrency)
        depth += 1
        next_frontier = []
        for path, response, err in results:
            visited.add(path)
            site.fetched += 1
            if err is not None:
                reporter.info(f"crawl {path}: {err}")
                continue
            if response.status_code in (404, 410):
                continue
            if path.endswith(".js"):
                site.js_files.add(path)
            else:
                site.pages.add(path)
            links, js_files, params, extra_seeds = _harvest(client.base_url, path, response)
            site.params |= params
            for candidate in extra_seeds | links | js_files:
                if candidate not in visited:
                    next_frontier.append(candidate)
        frontier = next_frontier
    reporter.info(
        f"Crawl discovered {len(site.pages)} page(s), {len(site.js_files)} script(s), "
        f"{len(site.params)} distinct parameter name(s) from {site.fetched} request(s)."
    )
    return site
