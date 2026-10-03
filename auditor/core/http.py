import threading
import time
import requests
from urllib.parse import urljoin, urlparse

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "apikey"}

# Transient network failures worth a short retry (never applied to 4xx/5xx responses,
# only to connection-level errors that a flaky link or brief server hiccup can cause).
RETRYABLE_EXCEPTIONS = (requests.ConnectionError, requests.Timeout)


def redact_headers(headers):
    return {k: ("<redacted>" if k.lower() in SENSITIVE_HEADERS else v)
            for k, v in headers.items()}


class HTTPClient:
    """Rate-limited HTTP client, safe to share across threads.

    A single lock serializes the "am I allowed to fire yet" check so
    concurrent callers (e.g. a thread pool fuzzing several paths at once)
    still collectively honor --rate requests/second against the target,
    rather than each thread keeping its own independent budget.
    """

    def __init__(self, base_url, timeout=10, rate=4.0, verify=True,
                 user_agent="auditor/0.8", retries=2, backoff=0.5):
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.min_interval = 1.0 / max(rate, 0.1)
        self.retries = max(retries, 0)
        self.backoff = max(backoff, 0.0)
        self._last = 0.0
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent, "Accept": "*/*"})
        self.verify = verify

    def url(self, path):
        return urljoin(self.base_url, path.lstrip("/"))

    def _throttle(self):
        with self._lock:
            now = time.monotonic()
            delay = self.min_interval - (now - self._last)
            if delay > 0:
                time.sleep(delay)
            self._last = time.monotonic()

    def request(self, method, path="", **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        attempt = 0
        while True:
            self._throttle()
            try:
                return self.session.request(method, self.url(path), **kwargs)
            except RETRYABLE_EXCEPTIONS:
                if attempt >= self.retries:
                    raise
                time.sleep(self.backoff * (2 ** attempt))
                attempt += 1

    def same_origin(self, url):
        a, b = urlparse(self.base_url), urlparse(url)
        return (a.scheme, a.netloc) == (b.scheme, b.netloc)
