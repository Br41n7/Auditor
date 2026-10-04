import json
import os
from dataclasses import dataclass, fields
from pathlib import Path
from urllib.parse import urlparse

PROFILES_DIR = Path(__file__).resolve().parent / "profiles"

# Fields a project file is allowed to set. Deliberately excludes tokens,
# keys and anything else secret: those always come from the environment
# or --flags, never from a file you might commit or hand to a teammate.
FILE_SETTABLE_FIELDS = {
    "target", "supabase_url", "profile", "timeout", "rate",
    "concurrency", "verify_tls", "max_pages", "max_depth", "strict_crawl",
}

def clean_url(value):
    value = (value or "").strip()
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    return value.rstrip("/")

@dataclass
class Config:
    target: str = ""
    supabase_url: str = ""
    anon_key: str = ""
    access_token: str = ""
    token_a: str = ""
    token_b: str = ""
    timeout: float = 10.0
    rate: float = 4.0
    concurrency: int = 1
    verify_tls: bool = True
    json_output: bool = False
    profile: str = "auto"
    paystack_secret_key: str = ""
    max_pages: int = 60
    max_depth: int = 3
    strict_crawl: bool = False

    @classmethod
    def from_env(cls, config_path=None):
        """Build a Config from (in increasing priority): defaults, an
        optional project file, then environment variables. CLI flags are
        applied by the caller afterward, so they always win last.
        """
        cfg = cls()
        if config_path:
            cfg = cfg.merge_file(config_path)
        env_map = {
            "target": ("AUDITOR_TARGET", clean_url),
            "supabase_url": ("AUDITOR_SUPABASE_URL", clean_url),
            "anon_key": ("AUDITOR_SUPABASE_ANON_KEY", str),
            "access_token": ("AUDITOR_ACCESS_TOKEN", str),
            "token_a": ("AUDITOR_TOKEN_A", str),
            "token_b": ("AUDITOR_TOKEN_B", str),
            "profile": ("AUDITOR_PROFILE", str),
            "paystack_secret_key": ("AUDITOR_PAYSTACK_SECRET_KEY", str),
        }
        for field_name, (env_var, cast) in env_map.items():
            val = os.getenv(env_var)
            if val:
                setattr(cfg, field_name, cast(val))
        if cfg.target:
            cfg.target = clean_url(cfg.target)
        if cfg.supabase_url:
            cfg.supabase_url = clean_url(cfg.supabase_url)
        return cfg

    def merge_file(self, path):
        """Layer non-secret settings from a JSON project file onto this
        config and return self. Unknown or secret-looking keys are ignored
        rather than raising, so a file can stay simple and forward-compatible.
        """
        data = json.loads(Path(path).read_text())
        valid_names = {f.name for f in fields(self)}
        for key, value in data.items():
            if key in FILE_SETTABLE_FIELDS and key in valid_names:
                setattr(self, key, value)
        return self

    @staticmethod
    def resolve_project_path(name):
        """Look up a bundled project profile by name, e.g. --project
        trendingevent -> auditor/profiles/trendingevent.json. Returns None
        if there's no such bundled file (the caller should then treat the
        given value as a literal path instead).
        """
        candidate = PROFILES_DIR / f"{name}.json"
        return candidate if candidate.is_file() else None

def require_http_url(value, name):
    value = clean_url(value)
    p = urlparse(value)
    if p.scheme not in {"http", "https"} or not p.netloc:
        raise ValueError(f"{name} must be a valid http(s) URL")
    return value
