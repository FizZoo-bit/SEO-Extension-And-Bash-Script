#!/usr/bin/env python3
"""
compare_runs.py — diff two pipeline_report_*.csv files.

Shows three things:
  1. NEW domains  — present in the newer report, not in the older one
  2. DROPPED domains — present in the older report, not in the newer one
     (usually means they weren't in this run's domains.txt at all,
     not that they were actively removed)
  3. CHANGED domains — present in both, but score/grade/status/
     index_status/available differ between runs

Reads columns by NAME (via csv.DictReader), not position, so it stays
correct even as the CSV schema grows (it already has twice — the
SQLite cache and the sub-score columns both added fields after this
tool would have been written).

Usage:
    compare_runs.py                       # auto: 2 most recent reports
    compare_runs.py old.csv new.csv        # explicit files
    compare_runs.py --reports-dir ./reports
"""
import csv
import sys
import os
import glob
import argparse


WATCHED_FIELDS = ['available', 'index_status', 'score', 'grade', 'status']


def load_report(path):
    """Load a CSV report into {domain: {field: value}}."""
    rows = {}
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get('domain', '').strip()
            if domain:
                rows[domain] = row
    return rows


def find_two_most_recent(reports_dir):
    candidates = sorted(
        glob.glob(os.path.join(reports_dir, 'pipeline_report_*.csv')),
        key=os.path.getmtime
    )
    if len(candidates) < 2:
        print(f"Need at least 2 report files in {reports_dir} to compare; found {len(candidates)}.", file=sys.stderr)
        sys.exit(1)
    return candidates[-2], candidates[-1]


def safe_float(val, default=0.0):
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def fmt_score(val):
    f = safe_float(val, None)
    return val if f is None else val


def diff_reports(old_path, new_path):
    old_rows = load_report(old_path)
    new_rows = load_report(new_path)

    old_domains = set(old_rows.keys())
    new_domains = set(new_rows.keys())

    only_new = sorted(new_domains - old_domains)
    only_old = sorted(old_domains - new_domains)
    common = sorted(old_domains & new_domains)

    changed = []
    for domain in common:
        old_row, new_row = old_rows[domain], new_rows[domain]
        diffs = {}
        for field in WATCHED_FIELDS:
            old_val = old_row.get(field, '')
            new_val = new_row.get(field, '')
            if old_val != new_val:
                diffs[field] = (old_val, new_val)
        if diffs:
            changed.append((domain, diffs, old_row, new_row))

    return only_new, only_old, changed, old_rows, new_rows


def print_report(old_path, new_path, only_new, only_old, changed):
    print(f"Comparing:")
    print(f"  OLD: {old_path}")
    print(f"  NEW: {new_path}")
    print()

    if only_new:
        print(f"── NEW domains ({len(only_new)}) — in this run, not the last one ──")
        for d in only_new:
            print(f"  + {d}")
        print()

    if only_old:
        print(f"── DROPPED domains ({len(only_old)}) — in the last run, not this one ──")
        for d in only_old:
            print(f"  - {d}")
        print(f"  (usually means they weren't in this run's domains.txt — not that they got worse)")
        print()

    if changed:
        # Sort by score movement (biggest improvement first, then biggest decline)
        def score_delta(item):
            _, diffs, old_row, new_row = item
            old_s = safe_float(old_row.get('score', 0))
            new_s = safe_float(new_row.get('score', 0))
            return new_s - old_s

        changed_sorted = sorted(changed, key=score_delta, reverse=True)

        print(f"── CHANGED domains ({len(changed)}) ──")
        for domain, diffs, old_row, new_row in changed_sorted:
            parts = []
            for field, (old_val, new_val) in diffs.items():
                if field == 'score':
                    delta = safe_float(new_val) - safe_float(old_val)
                    arrow = '↑' if delta > 0 else ('↓' if delta < 0 else '=')
                    parts.append(f"score {old_val}→{new_val} ({arrow}{abs(delta):.0f})")
                else:
                    parts.append(f"{field} {old_val}→{new_val}")
            print(f"  {domain:35s} {' | '.join(parts)}")
        print()

    if not only_new and not only_old and not changed:
        print("No differences found between these two reports.")

    total_old = len(only_old) + len(changed)  # rough common-set size proxy
    print(f"── Summary ──")
    print(f"  New: {len(only_new)}   Dropped: {len(only_old)}   Changed: {len(changed)}")


def main():
    parser = argparse.ArgumentParser(description="Diff two pipeline report CSVs.")
    parser.add_argument('old', nargs='?', help='Older report CSV (optional)')
    parser.add_argument('new', nargs='?', help='Newer report CSV (optional)')
    parser.add_argument('--reports-dir', default='./reports', help='Where to look for reports if old/new not given')
    args = parser.parse_args()

    if args.old and args.new:
        old_path, new_path = args.old, args.new
    elif args.old or args.new:
        print("Provide both old and new report paths, or neither (to auto-detect).", file=sys.stderr)
        sys.exit(1)
    else:
        old_path, new_path = find_two_most_recent(args.reports_dir)

    for p in (old_path, new_path):
        if not os.path.isfile(p):
            print(f"File not found: {p}", file=sys.stderr)
            sys.exit(1)

    only_new, only_old, changed, _, _ = diff_reports(old_path, new_path)
    print_report(old_path, new_path, only_new, only_old, changed)


if __name__ == '__main__':
    main()
