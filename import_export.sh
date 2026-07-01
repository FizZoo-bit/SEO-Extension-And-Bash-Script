#!/bin/bash
# import_export.sh — clean a manually-exported ExpiredDomains.net CSV
# (or any CSV/text export with domains in it) into domains.txt.
#
# This does NOT scrape or log into ExpiredDomains.net — it only
# processes a file you've already exported by hand through their
# normal web interface, exactly as before. It just automates the
# "copy/paste into Notepad and clean up the mess" step.
#
# WHY column-name-agnostic: ExpiredDomains.net's export format has
# shifted over the years (column sets, ordering, even row-count
# limits per the BlackHatWorld/NamePros threads), and we don't have
# a confirmed current header to hardcode against. Instead of guessing
# a column name/position and risking silent breakage on the real
# file, this scans every field in every row and keeps anything that
# matches valid domain syntax — robust to whatever the actual export
# looks like, at the cost of occasionally catching a non-domain field
# that happens to look like one (rare, and harmless: it just gets
# WHOIS-checked and filtered out by Stage 1 like any other bad entry).
#
# USAGE:
#   ./import_export.sh export.csv
#   ./import_export.sh export.csv -o domains.txt   (default)
#   ./import_export.sh export.csv -c               (skip cache check)
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

INPUT=""
OUTPUT="domains.txt"
CHECK_CACHE=1
CACHE_DB="./reports/domain_cache.sqlite3"
CACHE_MAX_AGE_DAYS=7

while [ $# -gt 0 ]; do
    case "$1" in
        -o) OUTPUT="$2"; shift 2 ;;
        -c) CHECK_CACHE=0; shift ;;
        -a) CACHE_MAX_AGE_DAYS="$2"; shift 2 ;;
        *)  INPUT="$1"; shift ;;
    esac
done

if [ -z "$INPUT" ]; then
    echo "Usage: $0 <export.csv> [-o domains.txt] [-c skip cache check] [-a max_age_days]" >&2
    exit 1
fi
[ -f "$INPUT" ] || { echo "File not found: $INPUT" >&2; exit 1; }

# ── Extract anything that looks like a domain from every field ────
# Domain regex: label(.label)+ where each label is alnum + optional
# internal hyphens, same pattern pipeline.sh's own validation uses.
# Applied per-CSV-field (not per-line) so it survives whatever column
# layout the export actually has, and handles comma-quoted fields
# reasonably via the simple approach of just splitting on common
# delimiters and testing each token.
RAW_EXTRACTED="/tmp/import_raw_$$_${RANDOM}"
tr ',;\t"' '\n' < "$INPUT" \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | grep -Ei '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' \
    | tr '[:upper:]' '[:lower:]' \
    > "$RAW_EXTRACTED" || true

n_extracted=$(wc -l < "$RAW_EXTRACTED" 2>/dev/null || echo 0)
if [ "$n_extracted" -eq 0 ]; then
    echo "No domain-like entries found in $INPUT — check the file format." >&2
    rm -f "$RAW_EXTRACTED"
    exit 1
fi

# ── Dedupe against itself and existing domains.txt ─────────────────
sort -u "$RAW_EXTRACTED" -o "$RAW_EXTRACTED"
n_unique=$(wc -l < "$RAW_EXTRACTED")

n_already_in_list=0
DEDUPED="/tmp/import_deduped_$$_${RANDOM}"
if [ -f "$OUTPUT" ] && [ -s "$OUTPUT" ]; then
    comm -23 "$RAW_EXTRACTED" <(sort -u "$OUTPUT") > "$DEDUPED"
    n_already_in_list=$(( n_unique - $(wc -l < "$DEDUPED") ))
else
    cp "$RAW_EXTRACTED" "$DEDUPED"
fi
n_after_list_dedup=$(wc -l < "$DEDUPED")

# ── Dedupe against the cache (skip domains already analyzed recently) ─
n_in_cache=0
FINAL="/tmp/import_final_$$_${RANDOM}"
if [ "$CHECK_CACHE" -eq 1 ] && [ -f "$CACHE_DB" ] && command -v sqlite3 &>/dev/null; then
    > "$FINAL"
    max_age_secs=$(( CACHE_MAX_AGE_DAYS * 86400 ))
    now=$(date +%s)
    cutoff=$(( now - max_age_secs ))
    while IFS= read -r domain; do
        cached_at=$(sqlite3 "$CACHE_DB" \
            "SELECT checked_at FROM domain_cache WHERE domain = '${domain//\'/\'\'}' LIMIT 1;" 2>/dev/null || true)
        if [ -n "$cached_at" ] && [ "$cached_at" -ge "$cutoff" ] 2>/dev/null; then
            (( n_in_cache++ )) || true
        else
            echo "$domain" >> "$FINAL"
        fi
    done < "$DEDUPED"
else
    cp "$DEDUPED" "$FINAL"
    [ "$CHECK_CACHE" -eq 1 ] && echo "Note: cache check skipped (sqlite3 not found or no cache DB yet)" >&2
fi
n_final=$(wc -l < "$FINAL" 2>/dev/null || echo 0)

# ── Append to domains.txt ───────────────────────────────────────────
if [ "$n_final" -gt 0 ]; then
    cat "$FINAL" >> "$OUTPUT"
fi

rm -f "$RAW_EXTRACTED" "$DEDUPED" "$FINAL"

echo "── Import summary ──────────────────────────"
echo "  Source file:            $INPUT"
echo "  Domain-like entries:     $n_extracted"
echo "  Unique entries:          $n_unique"
echo "  Already in $OUTPUT:      $n_already_in_list"
echo "  Already cached/checked:  $n_in_cache"
echo "  NEW domains added:       $n_final"
echo "  → $OUTPUT now ready for ./pipeline.sh"
