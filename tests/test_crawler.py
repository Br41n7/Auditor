from auditor.core.output import Reporter
from auditor.recon.crawler import crawl
from auditor.recon.discovery import candidate_paths, candidate_params, derive_words


class FakeResponse:
    def __init__(self, status_code, text="", content_type="text/html", url=""):
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": content_type}
        self.url = url
        self.content = text.encode()


class FakeClient:
    """Stands in for HTTPClient: same .request(method, path) interface,
    backed by an in-memory routing table instead of real sockets.
    """
    def __init__(self, routes, base_url="https://example.test"):
        self.routes = routes
        self.base_url = base_url

    def request(self, method, path, **kwargs):
        path = path.split("?")[0]
        if path in self.routes:
            ctype, body = self.routes[path]
            return FakeResponse(200, body, ctype, url=self.base_url + path)
        return FakeResponse(404, url=self.base_url + path)


ROUTES = {
    "/": ("text/html", '''
        <a href="/about">About</a>
        <a href="/products?category=shoes&sort=price">Products</a>
        <script src="/static/app.js"></script>
        <form action="/api/login" method="POST">
          <input name="username"><input name="password" type="password">
        </form>
        <a href="https://external.example/ignored">external</a>
        <a href="/logo.png">image</a>
    '''),
    "/about": ("text/html", '<a href="/api/orders?status=paid">orders</a>'),
    "/products": ("text/html", "products page"),
    "/static/app.js": ("application/javascript",
                        'fetch("/api/v1/admin/settings"); const e = "/api/cart/checkout";'),
    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /internal/dashboard\n"),
    "/sitemap.xml": ("application/xml",
                       "<urlset><url><loc>https://example.test/wishlist</loc></url></urlset>"),
    "/internal/dashboard": ("text/html", "dashboard"),
    "/wishlist": ("text/html", "wishlist"),
    "/api/login": ("application/json", "{}"),
    "/api/v1/admin/settings": ("application/json", "{}"),
    "/api/cart/checkout": ("application/json", "{}"),
}


def _crawl():
    client = FakeClient(ROUTES)
    reporter = Reporter(quiet=True)
    site = crawl(client, reporter, max_pages=30, max_depth=3, concurrency=1)
    return client, site


def test_crawl_discovers_linked_pages_and_skips_offsite_and_static_assets():
    _, site = _crawl()
    assert "/about" in site.pages
    assert "/products" in site.pages
    assert not any("external.example" in p for p in site.pages)
    assert not any(p.endswith(".png") for p in site.pages)


def test_crawl_follows_robots_disallow_and_sitemap_entries():
    _, site = _crawl()
    assert "/internal/dashboard" in site.pages
    assert "/wishlist" in site.pages


def test_crawl_extracts_routes_from_javascript_bundle():
    _, site = _crawl()
    assert "/api/v1/admin/settings" in site.pages
    assert "/api/cart/checkout" in site.pages
    assert "/static/app.js" in site.js_files
    assert "/static/app.js" not in site.pages


def test_crawl_collects_form_and_query_parameter_names():
    _, site = _crawl()
    assert {"username", "password", "category", "sort", "status"} <= site.params


def test_crawl_does_not_record_dead_links():
    routes = dict(ROUTES)
    routes["/"] = ("text/html", '<a href="/does-not-exist">dead</a>')
    client = FakeClient(routes)
    reporter = Reporter(quiet=True)
    site = crawl(client, reporter, max_pages=10, max_depth=2)
    assert "/does-not-exist" not in site.pages


def test_candidate_paths_prefers_discovery_over_fallback():
    client, _ = _crawl()
    client.discovered = crawl(client, Reporter(quiet=True), max_pages=30, max_depth=3)
    hits = candidate_paths(client, ("cart", "checkout"), fallback=["/should-not-appear"])
    assert hits == ["/api/cart/checkout"]


def test_candidate_paths_falls_back_when_nothing_discovered():
    client = FakeClient({})
    client.discovered = None
    hits = candidate_paths(client, ("cart",), fallback=["/api/checkout"])
    assert hits == ["/api/checkout"]


def test_candidate_params_matches_and_falls_back():
    client, _ = _crawl()
    client.discovered = crawl(client, Reporter(quiet=True), max_pages=30, max_depth=3)
    hits = candidate_params(client, ("status", "role"), fallback=set())
    assert hits == {"status"}
    empty_client = FakeClient({})
    empty_client.discovered = None
    assert candidate_params(empty_client, ("status",), fallback={"amount"}) == {"amount"}


def test_derive_words_pulls_segments_from_discovered_paths():
    client, _ = _crawl()
    client.discovered = crawl(client, Reporter(quiet=True), max_pages=30, max_depth=3)
    words = derive_words(client)
    assert "cart" in words and "checkout" in words and "admin" in words
