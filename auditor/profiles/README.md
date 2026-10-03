# Project profiles

Since you juggle several apps (TrendingEvent, VaultX, Academia AI, ...),
copy `example.json` to `<project>.json` in this folder and fill in the
non-secret settings for that project:

```json
{
  "target": "https://trendingevent.com.ng",
  "profile": "nextjs",
  "rate": 3.0,
  "concurrency": 4
}
```

Then run:

```bash
auditor --project trendingevent audit
```

`--project NAME` first looks for a bundled file named `NAME.json` in this
folder; if there isn't one, it treats `NAME` as a literal path, so
`--project ./my-profile.json` also works for a profile you keep outside
the package (e.g. alongside a client's project, not committed here).

**Never put tokens, API keys, or secrets in a profile file.** Only
`target`, `supabase_url`, `profile`, `timeout`, `rate`, `concurrency` and
`verify_tls` are read from it — anything else is ignored. Keep supplying
`--token-a` / `--token-b` / `AUDITOR_TOKEN_A` / `AUDITOR_TOKEN_B` (etc.)
the same way you already do, per run or via your shell environment.
