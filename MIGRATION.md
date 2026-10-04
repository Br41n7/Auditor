# Migration to v0.14.0

**`voting.surface` is now detection-gated.** It used to run on every
target in the `generic`/`django`/`nextjs` profiles, probing a hardcoded
`/api/vote`-style path list regardless of whether the target was a
voting platform. Now it only activates when the crawl itself shows real
evidence of one (`checks/voting.py:detect_voting_platform`, threshold
in `DETECTION_THRESHOLD`), and the hardcoded fallback path list for
voting is gone entirely -- every path it probes comes straight from
what the crawler found on that specific target. If detection doesn't
clear the bar, it logs that it skipped and why, instead of silently
doing nothing or running anyway.

**New `--strict-crawl` flag.** When set, `candidate_paths`/`candidate_params`
(`recon/discovery.py`) never fall back to a check's static guess list --
only what the crawl actually found, even if that's empty. Covers
recon's baseline path list and the candidate-path logic in payments/
business/files/auth/web. Explicit `--seed-common-paths`/`--seed-common-words`
still work under `--strict-crawl` (an explicit ask isn't an implicit
default); `fuzz`'s `.env`/`.git/HEAD`/`backup` safety-net list is
unaffected either way, since it was never crawl-discoverable in the
first place.

**Keyword matching is now token-based, not substring.** `recon/discovery.py`
gained `matches_keywords`/`keyword_signal_score`; a keyword like `poll`
now only matches a whole path segment (or a short plural of one), so
`/apollo-docs` no longer false-matches it. This is what makes the
voting-platform detection threshold meaningful -- without it, a
one-off substring hit would be enough to light up a whole check
category on an unrelated target.

**New `authz.id-predictability` check**, always on: flags when object
identifiers observed during the crawl look sequential/numeric
(`/api/orders/482`) rather than opaque (UUID), since that materially
changes how easy IDOR/BOLA enumeration is once one ID leaks. Entirely
derived from what the crawl saw; no guessing or enumeration performed.

# Migration to v0.13.0

**RLS/BOLA test plans from the relationship graph.** New `auditor/supabase/planner.py`,
wired to two new commands:

- `auditor supabase plan --schema FILE [--out plan.json]` — prints (or
  writes) the full test plan as JSON, no network calls, nothing executes.
  Every table in the schema gets a case: a direct PostgREST filter if it
  owns a user column itself, an embedded-resource filter built from the
  relationship chain if it doesn't (e.g. `payments.order_id -> orders.user_id`,
  arbitrary hop depth), or a `manual` case explaining why neither was
  possible.
- `auditor supabase sweep --schema FILE --user-a ID --user-b ID` — runs
  the plan: one cross-user GET per table. Replaces calling `auditor rls
  --table X --user-column Y ...` once per table by hand.

Along the way, `supabase/audit.py`'s cross-user probe (used by both
`rls` and the new sweep) got more accurate: a finding is now only
reported once a returned row is *verified* to carry the targeted user's
id, not just "the filtered request returned something non-empty." A
server that correctly ignores the filter and always returns the
caller's own rows no longer false-positives.

**Voting-process checks.** `vote`, `poll`, `ballot`, `candidate`,
`contestant`, `nominee`, `election` are now recognized entity names in
the crawler/matrix/prove tooling, so voting endpoints get picked up
automatically the same way `/api/orders/{id}` already did. A new
`voting.surface` check (auto-included in `audit`/`app`) covers surface
discovery, a CSRF-token signal on vote forms, a rate-limit header
signal, and cookie security flags on voting pages -- all read-only, by
design: it never submits a vote. See `examples/voting-flow.json` for
the business-flow-engine side (vote-count sanity, poll-status validity,
cross-voter ballot access) for use against your own test/staging
environment.

# Migration to v0.8.0

**The big change:** paths and parameters no longer come from static
hardcoded lists by default. `audit`, `recon`, `fuzz`, `app`, `business`
and `fuzz-input` now crawl the target first — same-origin links, forms,
`robots.txt`/`sitemap.xml`, and API routes pulled out of bundled JS —
and every check filters that discovered map for what's relevant to it.

New: `auditor --target <url> map` to inspect what the crawl found
without running any checks. New flags: `--max-pages`, `--max-depth`,
`--no-crawl` (old static-list-only behavior), `--seed-common-paths`,
`--seed-common-words` (add the old generic lists back *alongside*
whatever the crawl found, for targets where crawling alone falls short).

One static list remains on purpose: `fuzz`'s check for unlinked
sensitive artifacts (`.env`, `.git/HEAD`, `backup`) — these can't be
discovered by crawling since being unlinked is what makes them worth
checking for. Everything else that used to be a fixed guess-list —
`recon`'s common paths, `fuzz`'s wordlist, `payments`'/`business`'/
`files`'/`auth`'s candidate endpoints, `business`'s query-parameter
probes — now prefers what the crawl actually found on your project,
falling back to its old static list only if the crawl turned up
nothing usable there.

# Migration to v0.7.0

**Renamed:** the package and CLI entry point (formerly `fuhsi-audit` /
`fuhsiaudit`) are now `auditor` / `auditor`. Re-`pip install -e .`.
Environment variables have moved from `FUHSI_*` to `AUDITOR_*`
(`AUDITOR_TARGET`, `AUDITOR_TOKEN_A`, etc.), and generated finding IDs
now start with `AUD-` instead of `FUHSI-`.

## Faster scans: `--concurrency`

`recon` and `fuzz` can now check multiple paths in parallel instead of
one at a time:

```bash
auditor --target https://example.test --concurrency 8 recon
```

The `--rate` limit is still enforced across all workers combined (it's
now a shared, thread-safe budget), so raising `--concurrency` cuts wall
time without hammering the target harder than `--rate` allows. It
defaults to `1` (sequential), matching the old behavior.

## Automatic retries on flaky connections

`HTTPClient` now retries a request up to twice with a short backoff when
the failure is a connection error or timeout — not on any HTTP status
code, just on the network hiccups that used to abort a whole scan over
one dropped packet.

## Per-project profiles: `--project`

Running the same checks against TrendingEvent one day and another
project the next used to mean retyping `--target`, `--profile`, `--rate`
each time. Now:

```bash
auditor --project trendingevent audit
```

looks up `auditor/profiles/trendingevent.json` (create it from
`profiles/example.json`) for the non-secret settings — `target`,
`profile`, `timeout`, `rate`, `concurrency`, `verify_tls`. Tokens and
keys are never read from a profile file; keep passing those via
`--token-a`/`--token-b`/`AUDITOR_*` env vars as before. `--project` also
accepts a plain path (`--project ./client-a.json`) for a profile you
don't want committed alongside this tool.

## Migration to v0.6.0

## New business-logic surface checks

`business` performs low-impact discovery of common cart, checkout, order, wallet, coupon, refund and payment surfaces. It also reviews harmless query parameters such as `amount`, `price`, `quantity`, `role`, and `status`.

These are **review signals**, not proof that a business-logic vulnerability exists. Any state-changing integrity test must be explicitly designed for the application's test environment.

```bash
auditor --target https://example.test business
```

## New payment checks

`payments` can verify one transaction reference against Paystack using the owner's secret key. This uses the documented read-only transaction verification API and never initializes, charges, refunds, transfers, or otherwise mutates a transaction.

```bash
export AUDITOR_PAYSTACK_SECRET_KEY='sk_test_...'
auditor payments --reference YOUR_TEST_REFERENCE --expected-amount 500000 --expected-currency NGN
```

Use test-mode credentials and test transactions for development. Never put a Paystack secret key in source control or client-side code.

## Registry

The plugin registry now includes:

- `payments.surface`
- `business.surface`

## Compatibility

Existing v0.4 commands remain available. The JSON report schema is backward-compatible for existing finding fields; the tool version is now `0.6.0`.


## Business-flow engine

The new `flow` command accepts a JSON specification and performs only GET requests. It supports order/payment amount and currency equality, allowed states, non-negative numeric validation, explicit before/after state-transition assertions, and two-account cross-object authorization checks.

```bash
auditor --target https://example.test --token-a "$TOKEN_A" --token-b "$TOKEN_B" flow examples/business-flow.json
```

No order, payment, wallet, refund, or withdrawal mutation is performed by this command.


## v0.9
- Added `prove idor` and `prove cross-user` for controlled, read-only automatic reproduction of authorization findings.
- No state-changing automatic exploitation was added.

## 0.12.0
- Added `supabase map` for read-only relationship/RLS candidate mapping.
- Supports operator-supplied portable schema JSON or GET-only PostgREST OpenAPI discovery.
- No policy/row mutation is performed by the mapper.
