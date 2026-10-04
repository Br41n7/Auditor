import argparse
from .config import Config, require_http_url
from .core.http import HTTPClient
from .core.output import Reporter
from .recon.crawler import crawl
from .recon.discovery import candidate_paths
from .recon.scanner import endpoint_scan, header_scan, discovery, FALLBACK_COMMON_PATHS
from .fuzz.scanner import path_fuzz, build_wordlist
from .supabase.audit import audit as supabase_audit, rls_read_only
from .plugins.runner import run_project_checks, list_checks
from .checks.fuzzing import reflected_input, api_error_fuzz
from .checks.authz import idor_probe
from .checks.business import review_query_surface
from .checks.payments import verify_paystack_transaction
from .checks.flows import run_flow
from .checks.autoproof import prove_idor, prove_cross_user
from .reporting import render_markdown
from .mapping import build_attack_map
from .authorization.matrix import generate_candidates, run_matrix
from .supabase.schema_map import load_schema, build_supabase_map_from_postgrest
from .supabase.planner import plan_as_dict, write_plan, run_sweep

# Commands that operate against --target and benefit from crawling it first.
_CRAWLABLE_COMMANDS = {"audit", "recon", "fuzz", "app", "business", "fuzz-input", "map", "prove", "matrix"}

def build_parser():
    p = argparse.ArgumentParser(prog="auditor", description="Reusable, read-only-first security audit CLI for authorized testing.")
    p.add_argument("--target"); p.add_argument("--supabase-url"); p.add_argument("--anon-key")
    p.add_argument("--token"); p.add_argument("--token-a"); p.add_argument("--token-b")
    p.add_argument("--project", help="Load a bundled project profile by name (auditor/profiles/<name>.json), or a path to your own JSON profile. Never stores secrets -- tokens still come from --token/--token-a/--token-b or AUDITOR_* env vars.")
    p.add_argument("--timeout", type=float); p.add_argument("--rate", type=float)
    p.add_argument("--concurrency", type=int, help="Parallel requests for crawl/recon/fuzz (default 1 = sequential). The --rate limit is still enforced across all workers combined.")
    p.add_argument("--no-crawl", action="store_true", help="Skip crawling the target; checks fall back to their static guess lists instead of paths/params discovered from your project.")
    p.add_argument("--strict-crawl", action="store_true", help="Never fall back to a generic hardcoded path/param list when the crawl finds nothing matching -- checks report only what was actually discovered on this target, even if that's nothing. Does not affect explicit --seed-common-* flags or the fuzz safety-net artifact list.")
    p.add_argument("--max-pages", type=int, help="Cap on pages the crawler fetches (default 60).")
    p.add_argument("--max-depth", type=int, help="Cap on link-following depth while crawling (default 3).")
    p.add_argument("--seed-common-paths", action="store_true", help="Also probe a generic baseline path list alongside whatever the crawl discovers.")
    p.add_argument("--seed-common-words", action="store_true", help="Also fuzz a generic baseline wordlist alongside words harvested from the crawl.")
    p.add_argument("--insecure", action="store_true"); p.add_argument("--json", action="store_true", dest="json_output")
    p.add_argument("--paystack-secret-key"); p.add_argument("--quiet", action="store_true"); p.add_argument("--profile", choices=["auto","generic","django","nextjs"], default=None)
    p.add_argument("--out", help="Write JSON report to file")
    sub = p.add_subparsers(dest="command")
    for name in ("audit","recon","headers","fuzz","list-checks","map"): sub.add_parser(name)
    app = sub.add_parser("app"); app.add_argument("--profile", choices=["auto","generic","django","nextjs"], default=None); app.add_argument("--check", action="append", help="Run only this check id; repeatable")
    idor = sub.add_parser("idor"); idor.add_argument("--path", required=True); idor.add_argument("--id-a", required=True); idor.add_argument("--id-b", required=True)
    sub.add_parser("fuzz-input")
    matrix = sub.add_parser("matrix", help="Generate or execute a read-only two-account authorization matrix")
    matrix.add_argument("--spec", help="JSON matrix spec to execute")
    matrix.add_argument("--candidates", action="store_true", help="Print authorization candidates generated from the attack map")
    proof = sub.add_parser("prove", help="Automatically reproduce supported read-only findings; never performs state-changing exploitation")
    proof_sub = proof.add_subparsers(dest="proof_type", required=True)
    pi = proof_sub.add_parser("idor", help="Reproduce a suspected BOLA/IDOR using GET only")
    pi.add_argument("--path", required=True); pi.add_argument("--id-a", required=True); pi.add_argument("--id-b", required=True)
    pc = proof_sub.add_parser("cross-user", help="Run an explicit two-account GET authorization matrix")
    pc.add_argument("--path", required=True); pc.add_argument("--id-a", required=True); pc.add_argument("--id-b", required=True)
    biz = sub.add_parser("business")
    biz.add_argument("--path", default="/api/checkout", help="Optional endpoint for harmless query-surface review")
    flow = sub.add_parser("flow"); flow.add_argument("spec", help="JSON business-flow specification; GET-only")
    sup = sub.add_parser("supabase")
    sup_sub = sup.add_subparsers(dest="supabase_command")
    sup_sub.add_parser("audit", help="Run the standard Supabase audit")
    sm = sup_sub.add_parser("map", help="Map Supabase tables/relationships from a supplied schema or PostgREST OpenAPI")
    sm.add_argument("--schema", help="Path to a portable schema JSON; no network requests are made")
    sm.add_argument("--postgrest", action="store_true", help="Fetch PostgREST OpenAPI with GET using the supplied anon key")
    sp = sup_sub.add_parser("plan", help="Generate a safe RLS/BOLA test plan from the schema's relationship graph -- no tokens or network calls required")
    sp.add_argument("--schema", help="Path to a portable schema JSON; no network requests are made")
    sp.add_argument("--postgrest", action="store_true", help="Fetch PostgREST OpenAPI with GET using the supplied anon key")
    sp.add_argument("--tables", help="Comma-separated subset of tables to plan for (default: all)")
    sp.add_argument("--out", help="Write the plan JSON to this file instead of printing it")
    sw = sup_sub.add_parser("sweep", help="Execute the RLS/BOLA test plan: one cross-user GET per table, direct or via its relationship chain")
    sw.add_argument("--schema", help="Path to a portable schema JSON; no network requests are made for the map itself")
    sw.add_argument("--postgrest", action="store_true", help="Fetch PostgREST OpenAPI with GET using the supplied anon key")
    sw.add_argument("--tables", help="Comma-separated subset of tables to sweep (default: all)")
    sw.add_argument("--user-a", required=True, help="Account A's own user id/uuid (the value its owner columns hold)")
    sw.add_argument("--user-b", required=True, help="Account B's own user id/uuid -- the sweep checks whether token A can read rows belonging to this user")
    pay = sub.add_parser("payments")
    pay.add_argument("--reference", help="Your own Paystack transaction reference for read-only verification")
    pay.add_argument("--expected-amount", help="Expected gateway amount in subunits, e.g. 500000 for NGN 5,000")
    pay.add_argument("--expected-currency")
    rls = sub.add_parser("rls"); rls.add_argument("--table", required=True); rls.add_argument("--user-column", default="user_id"); rls.add_argument("--user-a", required=True); rls.add_argument("--user-b", required=True)
    report = sub.add_parser("report"); report.add_argument("file", help="JSON report generated with --out")
    return p

def _resolve_config_path(project_arg):
    if not project_arg:
        return None
    bundled = Config.resolve_project_path(project_arg)
    return str(bundled) if bundled else project_arg

def main(argv=None):
    args = build_parser().parse_args(argv)
    config_path = _resolve_config_path(args.project)
    cfg = Config.from_env(config_path=config_path)
    if args.target: cfg.target = require_http_url(args.target, "target")
    if args.supabase_url: cfg.supabase_url = require_http_url(args.supabase_url, "supabase-url")
    for attr, val in (("anon_key",args.anon_key),("access_token",args.token),("token_a",args.token_a),("token_b",args.token_b),("timeout",args.timeout),("rate",args.rate),("concurrency",args.concurrency),("paystack_secret_key", args.paystack_secret_key),("profile", args.profile),("max_pages", args.max_pages),("max_depth", args.max_depth)):
        if val is not None: setattr(cfg, attr, val)
    if args.strict_crawl: cfg.strict_crawl = True
    cfg.verify_tls = not args.insecure; cfg.json_output = args.json_output
    concurrency = max(cfg.concurrency or 1, 1)
    if not args.command: build_parser().print_help(); return 2
    if args.command == "list-checks":
        for c in list_checks(): print(f"{c.id:<24} {c.name} [{', '.join(c.profiles)}]")
        return 0
    if args.command == "report":
        import json, pathlib
        data=json.loads(pathlib.Path(args.file).read_text()); print(render_markdown(data)); return 0
    reporter=Reporter(json_mode=cfg.json_output, quiet=args.quiet)
    try:
        if args.command == "flow":
            if not cfg.target: raise ValueError("A target is required. Use --target, a --project profile, or AUDITOR_TARGET.")
            client=HTTPClient(cfg.target,cfg.timeout,cfg.rate,cfg.verify_tls,user_agent="auditor/0.14")
            run_flow(client, reporter, args.spec, cfg.token_a, cfg.token_b)
        elif args.command in {"audit","recon","headers","fuzz","app","fuzz-input","idor","business","map","prove","matrix"}:
            if not cfg.target: raise ValueError("A target is required. Use --target, a --project profile, or AUDITOR_TARGET.")
            client=HTTPClient(cfg.target,cfg.timeout,cfg.rate,cfg.verify_tls,user_agent="auditor/0.14")
            client.discovered = None
            client.strict_crawl = cfg.strict_crawl
            if not args.no_crawl and args.command in _CRAWLABLE_COMMANDS:
                client.discovered = crawl(client, reporter, max_pages=cfg.max_pages, max_depth=cfg.max_depth, concurrency=concurrency)
            elif args.command in {"audit","recon"}:
                discovery(client, reporter)  # crawl skipped: fall back to the old bare discovery ping
            if args.command == "map":
                site = client.discovered
                if not site or not (site.pages or site.js_files):
                    reporter.info("Nothing discovered. The target may sit behind auth, block automated clients, or serve no crawlable HTML/JS.")
                else:
                    attack_map = build_attack_map(client, site, include_openapi=True)
                    if args.json_output:
                        print(__import__("json").dumps(attack_map.as_dict(), indent=2))
                    else:
                        print("\n[ATTACK SURFACE]")
                        for ep in attack_map.endpoints:
                            print(f"  {','.join(ep.methods):<16} {ep.path} [{ep.source}]")
                        if attack_map.entities:
                            print("\n[ENTITIES]")
                            for ent in attack_map.entities:
                                owners = ", ".join(ent.likely_owner_fields) or "unknown"
                                print(f"  {ent.name:<14} owner={owners} paths={len(ent.paths)}")
                        if attack_map.relations:
                            print("\n[RELATIONS]")
                            for rel in attack_map.relations:
                                print(f"  {rel['endpoint']}: {' <-> '.join(rel['entities'])}")
                        if attack_map.openapi_url:
                            print(f"\n[OPENAPI] discovered at {attack_map.openapi_url}")
            if args.command == "matrix":
                if not args.spec and not args.candidates:
                    raise ValueError("matrix requires --spec to execute or --candidates to generate candidate cases")
                site = client.discovered
                attack_map = build_attack_map(client, site, include_openapi=True)
                candidates = generate_candidates(attack_map)
                if args.candidates:
                    if args.json_output:
                        print(__import__("json").dumps(candidates, indent=2))
                    else:
                        print("\n[AUTHORIZATION CANDIDATES]")
                        for c in candidates:
                            print(f"  {c['confidence'].upper():<6} {c['path']}  ({', '.join(c['placeholders'])})")
                if args.spec:
                    run_matrix(client, reporter, args.spec, cfg.token_a, cfg.token_b)
            if args.command in {"audit","recon"}:
                paths = list(client.discovered.all_paths()) if client.discovered else []
                if args.seed_common_paths or (not paths and not cfg.strict_crawl):
                    paths = list(dict.fromkeys(paths + FALLBACK_COMMON_PATHS))
                endpoint_scan(client,reporter,paths,concurrency=concurrency)
            if args.command in {"audit","headers"}: header_scan(client,reporter)
            if args.command in {"audit","fuzz"}:
                words = build_wordlist(client, include_generic=args.seed_common_words)
                path_fuzz(client,reporter,words=words,concurrency=concurrency)
            if args.command in {"audit","app"}:
                profile=getattr(args,"profile",None) or cfg.profile
                run_project_checks(client,reporter,cfg.access_token,profile,getattr(args,"check",None))
            if args.command == "prove":
                if not cfg.token_a or not cfg.token_b: raise ValueError("prove requires --token-a and --token-b.")
                if args.proof_type == "idor":
                    prove_idor(client, reporter, args.path, args.id_a, args.id_b, cfg.token_a, cfg.token_b)
                elif args.proof_type == "cross-user":
                    prove_cross_user(client, reporter, args.path, args.id_a, args.id_b, cfg.token_a, cfg.token_b)
            if args.command == "idor":
                if not cfg.token_a or not cfg.token_b: raise ValueError("IDOR checks require --token-a and --token-b.")
                idor_probe(client,reporter,args.path,args.id_a,args.id_b,cfg.token_a,cfg.token_b)
            if args.command == "fuzz-input":
                reflected_input(client,reporter)
                fuzz_paths = candidate_paths(client, ("api",), ["/api/users","/api/orders","/api/products"])
                api_error_fuzz(client,reporter,fuzz_paths)
            if args.command == "business":
                from .checks.business import scan as business_scan
                business_scan(client, reporter); review_query_surface(client, reporter, args.path)
        elif args.command == "payments":
            if not args.reference:
                raise ValueError("payments requires --reference for read-only Paystack verification")
            pay_client=HTTPClient("https://api.paystack.co", cfg.timeout, cfg.rate, cfg.verify_tls, user_agent="auditor/0.14")
            verify_paystack_transaction(pay_client, reporter, cfg.paystack_secret_key, args.reference, args.expected_amount, args.expected_currency)
        elif args.command == "supabase":
            cmd = args.supabase_command
            needs_schema = cmd in {"map", "plan", "sweep"}
            # sweep always needs a live client to execute the probes, even
            # when the schema itself came from a local file; map/plan only
            # need one if --postgrest discovery was requested.
            needs_client = cmd in (None, "audit", "sweep") or (needs_schema and args.postgrest)
            smap = None
            client = None
            if needs_client:
                if not cfg.supabase_url: raise ValueError("Supabase URL is required.")
                client=HTTPClient(cfg.supabase_url,cfg.timeout,cfg.rate,cfg.verify_tls)
            if cmd in (None, "audit"):
                supabase_audit(client,reporter,cfg.anon_key,cfg.access_token)
            elif needs_schema:
                if args.schema:
                    smap = load_schema(args.schema)
                elif args.postgrest:
                    if not cfg.anon_key: raise ValueError("--postgrest mapping requires --anon-key (read-only).")
                    r=client.request("GET", "/rest/v1/", headers={"apikey":cfg.anon_key,"Accept":"application/json"}, allow_redirects=False)
                    if r.status_code != 200: raise ValueError(f"PostgREST OpenAPI request returned HTTP {r.status_code}")
                    try: doc=r.json()
                    except Exception as exc: raise ValueError("PostgREST did not return JSON") from exc
                    smap=build_supabase_map_from_postgrest(doc)
                else:
                    raise ValueError(f"supabase {cmd} requires --schema FILE or --postgrest")
            if args.supabase_command == "map":
                if args.json_output:
                    print(__import__("json").dumps(smap.as_dict(), indent=2))
                else:
                    print("\n[SUPABASE TABLES]")
                    for t in smap.tables:
                        owners=", ".join(t.owner_fields) or "none detected"
                        print(f"  {t.name}: owners={owners}, columns={len(t.columns)}")
                    if smap.relationships:
                        print("\n[RELATIONSHIPS]")
                        for r in smap.relationships:
                            print(f"  {r.source_table}.{r.source_column} -> {r.target_table}.{r.target_column} [{r.confidence}]")
                    if smap.rls_candidates:
                        print("\n[RLS CANDIDATES]")
                        for c in smap.rls_candidates:
                            label = c['test'] if c['test'] != 'cross-user-select-chain' else f"cross-user-select (via {len(c['owner_path'])}-hop chain)"
                            print(f"  {c['table']} owner={c.get('owner_column') or 'unknown'} test={label}")
            elif args.supabase_command == "plan":
                tables = [t.strip() for t in args.tables.split(",")] if args.tables else None
                if args.out:
                    write_plan(smap, args.out, tables)
                    print(f"RLS/BOLA test plan written to {args.out} ({len(smap.rls_candidates if not tables else [c for c in smap.rls_candidates if c['table'] in tables])} case(s)).")
                else:
                    print(__import__("json").dumps(plan_as_dict(smap, tables), indent=2))
            elif args.supabase_command == "sweep":
                tables = [t.strip() for t in args.tables.split(",")] if args.tables else None
                run_sweep(client, reporter, smap, cfg.anon_key, cfg.token_a, cfg.token_b, args.user_a, args.user_b, tables)
        elif args.command == "rls":
            if not cfg.supabase_url or not cfg.anon_key: raise ValueError("RLS checks require --supabase-url and --anon-key.")
            if not cfg.token_a or not cfg.token_b: raise ValueError("RLS checks require --token-a and --token-b.")
            client=HTTPClient(cfg.supabase_url,cfg.timeout,cfg.rate,cfg.verify_tls); rls_read_only(client,reporter,cfg.anon_key,cfg.token_a,cfg.token_b,args.table,args.user_column,args.user_a,args.user_b)
    except KeyboardInterrupt: reporter.error("Interrupted."); return 2
    except ValueError as exc: reporter.error(str(exc)); return 2
    except Exception as exc: reporter.error(f"Unexpected error: {exc}"); return 2
    if args.out: reporter.write_json(args.out)
    if cfg.json_output: reporter.render_json()
    else: reporter.print_summary()
    return reporter.exit_code

if __name__ == "__main__": raise SystemExit(main())
