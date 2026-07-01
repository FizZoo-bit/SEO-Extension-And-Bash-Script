# Domain Hunter Toolkit

A command-line pipeline for vetting expired/dropped domains before you buy
them — built for PBN (private blog network) builders and domain investors
who currently do this by eyeballing a spreadsheet. It runs 12 automated
checks per domain (backlink profile, spam signals, index status, Wayback
history, blocklist status, and more), combines them into a single 0-100
score with a letter grade, and gives you a clean report instead of a gut
feeling.

**Status: active beta.** The scoring formula has gone through several real
rounds of correction against actual output (see [Scoring](#scoring) below)
and is still being tuned. Treat scores as a strong starting signal, not a
final verdict — and if a grade doesn't match your own judgment on a domain
you know well, that's expected feedback, not necessarily a bug. Everything
else (the pipeline mechanics, caching, error handling) has been stress-
tested across many real runs and is stable.

## What it actually checks

| Category | Signal |
|---|---|
| Availability | WHOIS (parallel) |
| Search presence | Google index status (`site:` query via DataForSEO SERP API) |
| Backlink profile | Domain rank, backlink/referring-domain counts, spam score, anchor text patterns, link-scheme detection |
| History | Wayback Machine snapshots, domain age, niche consistency over time, parking-page/thin-content detection |
| Reputation | Spamhaus Domain Blocklist (free DNS query — catches domains blacklisted by a *previous* owner) |
| Technical | `robots.txt` / `sitemap.xml` presence, current nameserver provider, referring-IP diversity, link velocity spikes |

Each domain gets a composite score built from four weighted sub-scores —
**Authority**, **Spam Risk**, **Link Profile**, **Stability** — so you can
see *why* a domain scored the way it did, not just the final number.

## What this costs

This is **bring-your-own-API-key**. You need:

- A [DataForSEO](https://dataforseo.com) account with the **Backlinks API
  activated** — this requires a one-time $100 minimum commitment, which
  becomes usable account balance (not a separate fee; you can spend it on
  any DataForSEO API). Activate it at
  `https://app.dataforseo.com/backlinks-subscription` before running this
  — without it, every backlink-dependent check fails with a `40204` error.
- Actual per-check usage is small. A 50-domain batch typically costs a few
  dollars in DataForSEO usage, well within the $100 you've already
  committed. The pipeline includes a free cheap-filter pass that skips
  paid checks entirely for domains with no positive signal at all (see
  below), so you're not paying for obviously empty domains.
- Everything else (Wayback Machine, Spamhaus, `robots.txt`/`sitemap.xml`,
  DNS lookups) is free, no account needed.

## Setup

```bash
sudo apt install jq sqlite3 whois curl dnsutils
echo -n "your@email.com:yourpassword" | base64   # DataForSEO Basic Auth
export DATAFORSEO_TOKEN="..."                     # add to ~/.bashrc to persist
chmod +x pipeline.sh add_domains.sh import_export.sh compare_runs.sh
```

Put one domain per line in `domains.txt` (blank lines and `#` comments
ignored).

## Usage

```bash
./pipeline.sh                  # default run: domains.txt, 5 parallel, cache on
./pipeline.sh -d other.txt      # use a different domain list
./pipeline.sh -j 8               # 8 parallel workers for the paid checks
./pipeline.sh -w 5                # 5 parallel WHOIS lookups
./pipeline.sh -c                   # disable cache, force a fresh check on everything
./pipeline.sh -a 14                 # cache max-age in days (default 7)
./pipeline.sh -e 0                   # disable the free cheap-check filter
```

```bash
streamlit run dashboard.py       # browse results in a web UI
python3 trend_report.py           # see score movement across repeat checks
./add_domains.sh new_paste.txt     # merge a fresh domain list into domains.txt, deduped
./import_export.sh export.csv       # clean a messy CSV export into domains.txt
./compare_runs.sh                    # diff your two most recent reports
```

## How it's fast

A naive version of this checks each domain fully, one paid call after
another. This pipeline doesn't:

- **Free signals run before paid ones, in parallel.** Index status,
  Wayback history, `robots.txt`/`sitemap.xml`, Spamhaus, and nameserver
  lookups all fire concurrently per domain — about 5x faster than running
  them sequentially.
- **A weighted cheap-check filter skips paid calls entirely** for domains
  with no positive signal across any free check (no Wayback history, not
  indexed, no sitemap, blocked robots.txt). On a typical batch of dropped
  domains, 60-85% never touch the paid API at all.
- **Results are cached** (SQLite, 7-day default window) — re-running an
  overlapping domain list skips WHOIS and all paid checks for anything
  checked recently.
- **Worker parallelism adapts.** If DataForSEO starts rate-limiting, the
  pipeline automatically reduces concurrency for the rest of the run
  instead of hammering a wall and burning retries.

## Scoring

Score = `(Authority×30 + SpamRisk×30 + LinkProfile×30 + Stability×10) / 100`,
each sub-score independently 0-100, plus a compounding penalty when 2+
severe red flags (link scheme, foreign gambling spam, single-host link
farm, redirect-away, severe link velocity spike, niche instability, spam
content) fire on the same domain.

This weighting is the result of two real corrections against actual
output, not guesswork from the start:

1. Authority was originally weighted higher, but a high-DR domain running
   a 969:1 link-scheme ratio with gambling-spam anchors was scoring a C
   instead of an F — high authority was masking real badness. Authority's
   weight was lowered and a compounding severity penalty added.
2. That fix then over-corrected: at 20% weight, Authority barely moved
   the final score at all (the full DR range from 0 to 400+ shifted the
   final score by only ~8 points), so domains with real backlink profiles
   and domains with none were landing in the same grade. Authority was
   raised back to 30% and its DR tiers were steepened to match what real
   PBN-candidate domains actually look like (most sit in the DR 10-60
   range, not DR 70+).

If you find another case where the grade clearly doesn't match reality,
that's useful — open an issue with the domain's report row.

## Known limitations

- No automated sourcing from ExpiredDomains.net or similar — by design.
  Programmatically logging into and scraping a site that only offers
  manual CSV export isn't something this project does; `import_export.sh`
  and `add_domains.sh` exist to make your own manual export/copy-paste
  faster to process, not to replace it.
- Historical DNS/hosting data (has a domain bounced through sketchy hosts
  over time) isn't checked — only current nameserver. The historical
  version requires a paid third-party feed (WhoisXML-style), which isn't
  included.
- Domain Authority-style trust metrics (Moz/Ahrefs/Majestic) aren't used —
  their free tiers cap around 10 queries/month and their paid tiers cost
  about the same as the DataForSEO endpoints already in use.
- The Google Cache check that older domain-checking tools include doesn't
  exist anymore for anyone — Google shut down public cache access in
  September 2024.

## Files

| File | What it does |
|---|---|
| `pipeline.sh` | Main entry point — runs the full check pipeline |
| `lib.sh` | All check logic, scoring, and caching functions |
| `dashboard.py` | Streamlit web UI for browsing results |
| `add_domains.sh` | Merge a fresh, clean domain paste into `domains.txt`, deduped |
| `import_export.sh` | Clean a messy CSV export (e.g. from ExpiredDomains.net) into `domains.txt` |
| `compare_runs.sh` / `compare_runs.py` | Diff your two most recent reports |
| `trend_report.py` | Show score movement for domains checked more than once |
