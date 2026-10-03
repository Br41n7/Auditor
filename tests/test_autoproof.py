from auditor.cli import build_parser


def test_prove_idor_parser_requires_values():
    p = build_parser()
    args = p.parse_args([
        "--target", "https://example.test",
        "--token-a", "A", "--token-b", "B",
        "prove", "idor", "--path", "/api/orders/{id}", "--id-a", "1", "--id-b", "2"
    ])
    assert args.proof_type == "idor"
    assert args.id_a == "1" and args.id_b == "2"


def test_prove_cross_user_parser():
    p = build_parser()
    args = p.parse_args(["--target", "https://example.test", "prove", "cross-user", "--path", "/api/orders/{id}", "--id-a", "1", "--id-b", "2"])
    assert args.proof_type == "cross-user"
