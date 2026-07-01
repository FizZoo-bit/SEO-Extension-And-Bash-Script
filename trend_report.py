#!/usr/bin/env python3
"""
trend_report.py — surfaces score movement over time per domain, using
the domain_history table (append-only, one row per fresh check) that
the pipeline now writes to alongside the normal cache.

This is different from compare_runs.py, which diffs two specific CSV
report files. trend_report.py looks across ALL history for domains
that have been checked more than once, regardless of which run each
check came from — it answers "is this domain's risk profile trending
up or down across however many times I've looked at it," not "what
changed between run A and run B."

Requires sqlite3 (Python's built-in sqlite3 module, not the CLI).

Usage:
    trend_report.py                          # all domains with 2+ history entries
    trend_report.py --min-checks 3           # only domains checked 3+ times
    trend_report.py --domain example.com     # full history for one domain
    trend_report.py --worsening              # only domains trending down
    trend_report.py --improving              # only domains trending up
"""
import sqlite3
import sys
import os
import argparse


def find_cache_db():
    candidates = [
        os.path.join('.', 'reports', 'domain_cache.sqlite3'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports', 'domain_cache.sqlite3'),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def load_history(db_path, domain_filter=None, min_checks=2):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='domain_history'")
    if not cur.fetchone():
        conn.close()
        print("This cache database predates the trend-tracking feature (no domain_history table).", file=sys.stderr)
        print("Run the pipeline at least once more — history starts building from now on.", file=sys.stderr)
        sys.exit(1)

    query = "SELECT domain, checked_at, score, grade, authority, spam_risk, link_profile, stability FROM domain_history"
    params = []
    if domain_filter:
        query += " WHERE domain = ?"
        params.append(domain_filter)
    query += " ORDER BY domain, checked_at ASC"

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    by_domain = {}
    for r in rows:
        by_domain.setdefault(r['domain'], []).append(dict(r))

    if not domain_filter:
        by_domain = {d: h for d, h in by_domain.items() if len(h) >= min_checks}

    return by_domain


def trend_summary(history):
    """Returns (first_score, last_score, delta, direction) for a domain's history list."""
    if len(history) < 2:
        return None
    first = history[0]['score']
    last = history[-1]['score']
    delta = last - first
    if delta > 2:
        direction = 'IMPROVING'
    elif delta < -2:
        direction = 'WORSENING'
    else:
        direction = 'STABLE'
    return first, last, delta, direction


def print_full_history(domain, history):
    print(f"\n{domain} — {len(history)} checks")
    for h in history:
        import datetime
        ts = datetime.datetime.fromtimestamp(h['checked_at']).strftime('%Y-%m-%d %H:%M')
        print(f"  {ts}  score={h['score']:>3} grade={h['grade']:<2} "
              f"(auth={h['authority']:>3} spam_risk={h['spam_risk']:>3} "
              f"link={h['link_profile']:>3} stab={h['stability']:>3})")


def main():
    parser = argparse.ArgumentParser(description="Show domain score trends from check history.")
    parser.add_argument('--domain', help='Show full history for a single domain')
    parser.add_argument('--min-checks', type=int, default=2, help='Minimum number of checks to include (default 2)')
    parser.add_argument('--worsening', action='store_true', help='Only show domains trending down')
    parser.add_argument('--improving', action='store_true', help='Only show domains trending up')
    parser.add_argument('--db', help='Path to domain_cache.sqlite3 (auto-detected if not given)')
    args = parser.parse_args()

    db_path = args.db or find_cache_db()
    if not db_path:
        print("Could not find domain_cache.sqlite3 — pass --db explicitly, or run the pipeline at least", file=sys.stderr)
        print("twice on overlapping domains first (history only builds up after repeat checks).", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(db_path):
        print(f"Database file not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    if args.domain:
        history = load_history(db_path, domain_filter=args.domain)
        if args.domain not in history or not history[args.domain]:
            print(f"No history found for {args.domain}. Either it's never been checked, or this is its first check.")
            sys.exit(0)
        print_full_history(args.domain, history[args.domain])
        return

    by_domain = load_history(db_path, min_checks=args.min_checks)
    if not by_domain:
        print(f"No domains found with {args.min_checks}+ checks in history yet.")
        print("Trend data builds up as you re-run the pipeline on overlapping domain lists over time.")
        return

    rows = []
    for domain, history in by_domain.items():
        summary = trend_summary(history)
        if not summary:
            continue
        first, last, delta, direction = summary
        rows.append((domain, len(history), first, last, delta, direction))

    if args.worsening:
        rows = [r for r in rows if r[5] == 'WORSENING']
    elif args.improving:
        rows = [r for r in rows if r[5] == 'IMPROVING']

    if not rows:
        print("No domains match the filter.")
        return

    rows.sort(key=lambda r: r[4])  # sort by delta, most negative (worst trend) first

    print(f"{'Domain':<35} {'Checks':>7} {'First':>6} {'Last':>6} {'Δ':>5}  Trend")
    print("-" * 80)
    for domain, n_checks, first, last, delta, direction in rows:
        sign = '+' if delta > 0 else ''
        print(f"{domain:<35} {n_checks:>7} {first:>6} {last:>6} {sign}{delta:>4}  {direction}")

    n_worsening = sum(1 for r in rows if r[5] == 'WORSENING')
    n_improving = sum(1 for r in rows if r[5] == 'IMPROVING')
    n_stable = sum(1 for r in rows if r[5] == 'STABLE')
    print(f"\n{len(rows)} domain(s) with history — {n_improving} improving, {n_worsening} worsening, {n_stable} stable")


if __name__ == '__main__':
    main()
