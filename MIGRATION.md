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
