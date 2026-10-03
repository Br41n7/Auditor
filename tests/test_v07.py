import json

from auditor.cli import build_parser
from auditor.config import Config
from auditor.core.http import HTTPClient


def test_project_profile_merges_non_secret_fields(tmp_path):
    profile = tmp_path / "myproj.json"
    profile.write_text(json.dumps({
        "target": "example.com",
        "profile": "nextjs",
        "rate": 2.5,
        "concurrency": 6,
        # secret-shaped key should be silently ignored, never stored
        "paystack_secret_key": "sk_live_should_not_be_read",
    }))
    cfg = Config.from_env(config_path=str(profile))
    assert cfg.target == "https://example.com"  # clean_url adds scheme
    assert cfg.profile == "nextjs"
    assert cfg.rate == 2.5
    assert cfg.concurrency == 6
    assert cfg.paystack_secret_key == ""  # ignored: not a file-settable field


def test_cli_accepts_project_and_concurrency_flags():
    p = build_parser()
    args = p.parse_args(["--project", "./whatever.json", "--concurrency", "8", "audit"])
    assert args.project == "./whatever.json"
    assert args.concurrency == 8


def test_bundled_example_profile_resolves_by_name():
    path = Config.resolve_project_path("example")
    assert path is not None and path.name == "example.json"


def test_unknown_project_name_is_not_resolved():
    assert Config.resolve_project_path("definitely-not-a-bundled-profile") is None


def test_http_client_is_thread_safe_rate_limited():
    client = HTTPClient("https://example.com", rate=100.0)
    assert client._lock is not None
    assert client.retries == 2  # default gives transient network hiccups a couple of retries
