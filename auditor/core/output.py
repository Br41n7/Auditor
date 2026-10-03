import json
import threading
from pathlib import Path
from .models import Finding

class Reporter:
    def __init__(self, json_mode=False, quiet=False):
        self.json_mode = json_mode
        self.quiet = quiet
        self.findings: list[Finding] = []
        self.messages: list[str] = []
        # Checks can run concurrently (see --concurrency), so guard the
        # shared lists and keep printed lines from interleaving mid-row.
        self._lock = threading.Lock()

    def add(self, finding: Finding):
        with self._lock:
            self.findings.append(finding)
            if not self.json_mode and not self.quiet:
                sev = finding.severity.upper()
                print(f"[{sev:<8}] {finding.check_id:<14} {finding.title}")
                if finding.evidence: print(f"  Evidence: {finding.evidence}")
                if finding.recommendation: print(f"  Fix:      {finding.recommendation}")

    def info(self, message: str):
        with self._lock:
            self.messages.append(message)
            if not self.json_mode and not self.quiet: print(f"[INFO    ] {message}")

    def error(self, message: str):
        with self._lock:
            self.messages.append("ERROR: " + message)
            if not self.json_mode: print(f"[ERROR   ] {message}")

    def print_summary(self):
        """End-of-run totals, printed once after all checks finish."""
        if self.json_mode:
            return
        s = self.summary()
        counts = s["by_severity"]
        parts = ", ".join(f"{k}={v}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if (v := counts.get(k, 0)))
        print(f"\n[SUMMARY ] {s['total']} finding(s) — {parts or 'none'}")

    def as_dict(self):
        return {
            "tool": "auditor",
            "version": "0.11.0",
            "findings": [f.as_dict() for f in self.findings],
            "summary": self.summary(),
        }

    def summary(self):
        counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for f in self.findings: counts[f.severity] = counts.get(f.severity, 0) + 1
        return {"total": len(self.findings), "by_severity": counts}

    def render_json(self): print(json.dumps(self.as_dict(), indent=2))

    def write_json(self, path: str):
        Path(path).write_text(json.dumps(self.as_dict(), indent=2), encoding="utf-8")

    @property
    def exit_code(self):
        return 1 if any(f.severity in {"CRITICAL", "HIGH"} for f in self.findings) else 0
