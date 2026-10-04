from auditor.core.output import Reporter
from auditor.recon.discovery import candidate_paths, matches_keywords, keyword_signal_score
from auditor.checks.voting import detect_voting_platform, scan as voting_scan, DETECTION_THRESHOLD
from auditor.checks.idpredictability import scan as id_scan


class FakeResponse:
    def __init__(self, status_code=200, text="", content_type="text/html", url="https://example.test/"):
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": content_type}
        self.url = url
        self.content = text.encode()


class FakeSite:
    def __init__(self, pages=(), js_files=(), params=()):
        self.pages = set(pages)
        self.js_files = set(js_files)
        self.params = set(params)

    def all_paths(self):
        return sorted(self.pages | self.js_files)


class FakeClient:
    def __init__(self, discovered=None, strict_crawl=False, base_url="https://example.test"):
        self.discovered = discovered
        self.strict_crawl = strict_crawl
        self.base_url = base_url

    def request(self, method, path, **kwargs):
        return FakeResponse(404, url=self.base_url + path)


def test_token_matching_rejects_substring_false_positive():
    # 'poll' must not match inside 'apollo' -- whole-token only.
    assert not matches_keywords("/apollo-docs", ("poll",))
    assert matches_keywords("/api/polls", ("poll",))
    assert matches_keywords("/api/vote", ("vote",))


def test_candidate_paths_respects_strict_crawl_on_empty_crawl():
    client = FakeClient(discovered=None, strict_crawl=True)
    assert candidate_paths(client, ("cart",), fallback=["/api/checkout"]) == []
    client2 = FakeClient(discovered=None, strict_crawl=False)
    assert candidate_paths(client2, ("cart",), fallback=["/api/checkout"]) == ["/api/checkout"]


def test_candidate_paths_respects_strict_crawl_on_no_match():
    site = FakeSite(pages={"/about", "/contact"})
    client = FakeClient(discovered=site, strict_crawl=True)
    assert candidate_paths(client, ("cart",), fallback=["/api/checkout"]) == []
    client2 = FakeClient(discovered=site, strict_crawl=False)
    assert candidate_paths(client2, ("cart",), fallback=["/api/checkout"]) == ["/api/checkout"]


def test_keyword_signal_score_weights_strong_over_supporting():
    site = FakeSite(pages={"/api/vote"})
    client = FakeClient(discovered=site)
    score = keyword_signal_score(client, {"vote"}, {"poll"})
    assert score == 2  # one strong match


def test_voting_detection_requires_real_signal_not_one_stray_word():
    # A single page whose path just happens to contain 'poll' as a whole
    # segment, with nothing else voting-related, should not clear the bar.
    site = FakeSite(pages={"/api/poll"})
    client = FakeClient(discovered=site)
    assert detect_voting_platform(client) < DETECTION_THRESHOLD


def test_voting_detection_fires_on_real_voting_signal():
    site = FakeSite(pages={"/api/vote", "/api/candidates"}, params={"candidate_id"})
    client = FakeClient(discovered=site)
    assert detect_voting_platform(client) >= DETECTION_THRESHOLD


def test_voting_scan_is_silent_without_detection():
    site = FakeSite(pages={"/about", "/apollo-docs"})
    client = FakeClient(discovered=site)
    reporter = Reporter(quiet=True)
    voting_scan(client, reporter)
    assert reporter.findings == []


def test_voting_scan_runs_when_detected():
    site = FakeSite(pages={"/api/vote", "/api/ballots"}, params={"candidate_id"})
    client = FakeClient(discovered=site)
    reporter = Reporter(quiet=True)
    voting_scan(client, reporter)
    # ran (even if no findings, it should have logged detection + probed paths)
    assert any("Voting-platform signal detected" in m for m in reporter.messages)


def test_id_predictability_flags_numeric_but_not_uuid_only():
    site = FakeSite(pages={"/api/orders/482", "/api/orders/483", "/api/tickets/3fae1c2b-aaaa-bbbb-cccc-1234567890ab"})
    client = FakeClient(discovered=site)
    reporter = Reporter(quiet=True)
    id_scan(client, reporter)
    assert len(reporter.findings) == 1
    assert "sequential/numeric" in reporter.findings[0].title


def test_id_predictability_silent_when_no_crawl_or_no_numeric_ids():
    client = FakeClient(discovered=None)
    reporter = Reporter(quiet=True)
    id_scan(client, reporter)
    assert reporter.findings == []

    site = FakeSite(pages={"/api/tickets/3fae1c2b-aaaa-bbbb-cccc-1234567890ab"})
    client2 = FakeClient(discovered=site)
    reporter2 = Reporter(quiet=True)
    id_scan(client2, reporter2)
    assert reporter2.findings == []
