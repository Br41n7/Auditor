# auditor v0.8.0

Reusable, **read-only-first** security auditing CLI for authorized testing of web applications, REST APIs and Supabase-backed projects.

## Attacker-perspective discovery (crawling)

Every check used to probe a static, hardcoded guess-list of paths. Now
`audit`/`recon`/`fuzz`/`app`/`business`/`fuzz-input` first **crawl your
actual target** the way a human doing recon would, and every check
draws its candidate paths/parameters from what's actually there:

- follows same-origin `<a href>`, `<form action>`, `<script src>` links
- reads `robots.txt` `Disallow` lines (often a map of what the owner
  didn't want indexed — admin panels, internal tools) and `sitemap.xml`
- pulls API-shaped routes out of bundled JS (`fetch("/api/...")`-style
  string literals)
- collects real parameter names from form inputs and query strings

See what it found before running anything:

```bash
auditor --target https://trendingevent.com.ng map
```

Then every check filters that discovered map for what's relevant to
it — `payments` checks look for pay/checkout/wallet-shaped paths,
`business` looks for cart/order/coupon-shaped paths, `fuzz` guesses
filenames built from words your own app actually uses (e.g. `vote`,
`ticket`) instead of a one-size-fits-all list, and so on.

**What still can't be crawled:** a handful of well-known sensitive
artifacts (`.env`, `.git/HEAD`, a stray `backup`) are never linked from
anywhere by definition — that's what makes them worth checking for. So
`fuzz` keeps a small, explicit safety-net list for exactly those, on
top of the words it derives from your crawl. If a target sits behind
auth the crawler never logs into, or crawling finds nothing at all,
each check falls back to its old static list rather than running empty
— pass `--seed-common-paths` / `--seed-common-words` to include the
generic baseline lists *alongside* whatever the crawl finds, or
`--no-crawl` to skip crawling entirely.

Useful flags: `--max-pages` (default 60), `--max-depth` (default 3),
`--concurrency` (parallel fetches during the crawl itself, too).

## Working across multiple projects

Instead of retyping `--target`/`--profile`/`--rate` every time you switch
between projects, save non-secret settings per project once:

```bash
cp auditor/profiles/example.json auditor/profiles/trendingevent.json
# edit trendingevent.json: target, profile, rate, concurrency
auditor --project trendingevent audit
```

`--project` also accepts a plain file path (`--project ./client-a.json`)
for a profile you'd rather not keep inside this repo. It never reads
tokens or keys from the file — those still come from `--token-a`,
`--token-b`, `--token`, or the `AUDITOR_*` environment variables below.
See `auditor/profiles/README.md` for details.

## Faster scans

`recon` and `fuzz` (and the crawl step itself) can check multiple paths
in parallel:

```bash
auditor --project trendingevent --concurrency 8 recon
```

`--rate` (requests/second) is still enforced as a shared budget across
all workers, so this cuts wall-clock time without exceeding the rate
limit you set. Default is `--concurrency 1` (sequential, as before).
Connection errors and timeouts are now retried automatically with a
short backoff before a check is reported as failed.

## What v0.5 adds

### Business-logic surface review

The scanner identifies common business surfaces such as:

- products and pricing
- carts and checkout
- orders and tickets
- coupons/discounts
- wallets and withdrawals
- refunds
- payment endpoints

It also looks for client-visible business control fields (`amount`, `price`, `quantity`, `discount`, `role`, `status`, ownership IDs). These findings are review signals, not automatic proof of exploitability.

```bash
auditor --target https://example.test business
```

For a particular checkout endpoint, it can perform harmless GET query-surface checks:

```bash
auditor --target https://example.test business --path /api/checkout
```

### Payment-integrity review

The generic application scan includes payment-surface discovery. For Paystack integrations, v0.5 also supports a read-only verification command using **your own test transaction** and Paystack secret key:

```bash
export AUDITOR_PAYSTACK_SECRET_KEY='sk_test_...'
auditor payments \
  --reference YOUR_TEST_REFERENCE \
  --expected-amount 500000 \
  --expected-currency NGN
```

The command only calls Paystack's transaction verification endpoint. It does not create charges or perform refunds/transfers.

The checks specifically help catch application-side mistakes such as:

- fulfilling an order without confirming gateway success
- accepting a verified amount that differs from the server-side order total
- accepting the wrong currency
- double-fulfilling a transaction
- treating a public verification route as sufficient authorization
- processing webhook events without origin/signature validation

Paystack documentation states that transaction verification is performed server-side using the transaction reference and that webhook events should be authenticated with the `x-paystack-signature` HMAC or documented IP allowlisting.


## Business-flow integrity engine

Version 0.6 adds a declarative, **GET-only** flow engine. Provide a small JSON specification describing the resources and invariants that matter to your project. The engine can compare order/payment amounts and currencies, validate allowed states, flag negative numeric values, check configured state transitions, and run a two-user cross-object authorization matrix.

```bash
auditor --target https://example.test \
  --token-a "$TOKEN_A" --token-b "$TOKEN_B" \
  flow examples/business-flow.json
```

The specification contains no secrets; tokens are supplied through the CLI/environment. This detects configured business-invariant violations; it does not automatically prove exploitability. State-changing tests such as duplicate fulfillment, refunds, wallet withdrawals, or price mutation should be explicitly designed for a controlled test environment.

## Main commands

```bash
auditor --target https://example.test map     # see what the crawler found, run nothing
auditor --target https://example.test audit
auditor --target https://example.test recon
auditor --target https://example.test app --profile django
auditor --target https://example.test app --profile nextjs
auditor --target https://example.test business
auditor --target https://example.test fuzz
auditor list-checks

# equivalently, once a profile file exists:
auditor --project trendingevent audit --concurrency 6
```

## Supabase

```bash
export AUDITOR_SUPABASE_URL=https://YOUR_PROJECT.supabase.co
export AUDITOR_SUPABASE_ANON_KEY='YOUR_PUBLIC_ANON_KEY'
auditor supabase
```

Two-account RLS testing:

```bash
auditor \
  --supabase-url "$AUDITOR_SUPABASE_URL" \
  --anon-key "$AUDITOR_SUPABASE_ANON_KEY" \
  --token-a "$TOKEN_A" --token-b "$TOKEN_B" \
  rls --table orders --user-column user_id --user-a "$USER_A" --user-b "$USER_B"
```

## Generic BOLA/IDOR testing

```bash
auditor \
  --target https://example.test \
  --token-a "$TOKEN_A" --token-b "$TOKEN_B" \
  idor --path /api/orders/{id} --id-a "$ORDER_A" --id-b "$ORDER_B"
```

## Reporting

```bash
auditor --target https://example.test audit --out audit.json
auditor report audit.json > report.md
```

## Safety boundary

The tool is intentionally **read-only-first**. It does not implement credential stuffing, destructive mutation, exploit delivery, shell payloads, stealth/evasion, or high-volume scanning. Authorization tests require credentials for accounts you are permitted to test.

For payment testing, use Paystack test-mode credentials and test transactions whenever possible. Paystack documents separate test/live environments and recommends keeping secret keys secure.

Only scan systems you own or have explicit permission to assess.

## Automatic proof-of-impact (v0.9)

When all required values are supplied, `prove` can automatically reproduce supported authorization findings. This is deliberately limited to **non-destructive GET requests**: it can prove a read-only BOLA/IDOR, but it will not create orders, change prices, issue refunds, withdraw funds, replay payments, execute arbitrary payloads, or otherwise mutate application state.

Two-account IDOR proof:

```bash
auditor \
  --target https://example.test \
  --token-a "$TOKEN_A" --token-b "$TOKEN_B" \
  prove idor \
  --path /api/orders/{id} \
  --id-a "$ORDER_A" --id-b "$ORDER_B"
```

Explicit authorization matrix:

```bash
auditor \
  --target https://example.test \
  --token-a "$TOKEN_A" --token-b "$TOKEN_B" \
  prove cross-user \
  --path /api/orders/{id} \
  --id-a "$ORDER_A" --id-b "$ORDER_B"
```

The proof runner records whether A can read A's object, A can read B's object, and B can read B's object. A successful cross-user read is reported as a reproduced high-confidence authorization finding.

For state-changing business-logic vulnerabilities, use a dedicated staging/test environment and explicit test fixtures rather than an unrestricted automatic exploit mode.

## v0.11 — Authorization matrix

Generate candidate read-only object-authorization cases from the attack map:

```bash
auditor --target https://example.test matrix --candidates
```

Execute an explicit two-account matrix from a fixture specification:

```bash
auditor --target https://example.test \
  --token-a "$TOKEN_A" --token-b "$TOKEN_B" \
  matrix --spec examples/authorization-matrix.json
```

Matrix execution uses GET requests only. It requires concrete fixtures and two operator-supplied test-account tokens; it does not create, modify, delete, refund, withdraw, or replay transactions.


### Supabase relationship mapping

Map a supplied schema without network access:

```bash
auditor supabase map --schema examples/supabase-schema.json
```

Or read the PostgREST OpenAPI document with GET using the anon key:

```bash
auditor --supabase-url https://YOUR_PROJECT.supabase.co --anon-key "$SUPABASE_ANON_KEY" supabase map --postgrest
```

The mapper identifies tables, likely owner columns, simple foreign-key relationships, and safe RLS test candidates. It does not modify rows or policies.
