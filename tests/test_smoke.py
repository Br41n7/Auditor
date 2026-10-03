from auditor.cli import build_parser

def test_parser():
    p = build_parser()
    args = p.parse_args(["--target", "https://example.com", "audit"])
    assert args.command == "audit"
    assert args.target == "https://example.com"
