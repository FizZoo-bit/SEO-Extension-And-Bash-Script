#!/bin/bash
# add_domains.sh — safely merge a fresh paste of domain names into
# domains.txt, skipping exact duplicates already in the file and
# (optionally) domains already checked recently in the cache.
#
# Unlike import_export.sh (built for messy ExpiredDomains.net CSV
# exports with junk metadata columns), this assumes the input is
# ALREADY clean — one domain per line, nothing else — which is what
# a direct copy-paste from the site's page actually produces. No CSV
# parsing, no column-guessing, just dedup.
#
# USAGE:
#   Paste domains into a file, then:
#   ./add_domains.sh pasted.txt
#
#   Or pipe directly from clipboard (Linux, requires xclip):
#   xclip -selection clipboard -o | ./add_domains.sh -
#
#   Options:
#   -o domains.txt   output file to merge into (default: domains.txt)
#   -c                skip the cache check, only dedupe against domains.txt
#   -a 7              cache max-age in days (default 7, matches pipeline.sh)
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

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
    echo "Usage: $0 <pasted_domains.txt | -> [-o domains.txt] [-c] [-a max_age_days]" >&2
    echo "  Use '-' to read from stdin (e.g. piped from xclip)." >&2
    exit 1
fi

if [ "$INPUT" = "-" ]; then
    RAW="/tmp/add_domains_stdin_$$_${RANDOM}"
    cat > "$RAW"
else
    [ -f "$INPUT" ] || { echo "File not found: $INPUT" >&2; exit 1; }
    RAW="$INPUT"
fi

# ── Clean and dedupe the input itself ──────────────────────────────
# Strip whitespace, blank lines, and lowercase for consistent
# comparison against domains.txt (domain matching should be
# case-insensitive even though we preserve original casing on write).
CLEANED="/tmp/add_domains_cleaned_$$_${RANDOM}"
sed 's/^[[:space:]]*//;s/[[:space:]]*$//' "$RAW" \
    | grep -v '^$' \
    | grep -v '^#' \
    > "$CLEANED" || true

n_pasted=$(wc -l < "$CLEANED" 2>/dev/null || echo 0)
if [ "$n_pasted" -eq 0 ]; then
    echo "No domains found in input." >&2
    [ "$INPUT" = "-" ] && rm -f "$RAW"
    rm -f "$CLEANED"
    exit 1
fi

sort -uf "$CLEANED" -o "$CLEANED"
n_unique_pasted=$(wc -l < "$CLEANED")

# ── Dedupe against existing domains.txt (case-insensitive) ────────
n_already_in_list=0
DEDUPED="/tmp/add_domains_deduped_$$_${RANDOM}"
if [ -f "$OUTPUT" ] && [ -s "$OUTPUT" ]; then
    # comm has no case-insensitive flag — lowercase both sides into
    # temp files for the comparison itself, but write the ORIGINAL
    # (correctly-cased) pasted lines to DEDUPED, not the lowercased
    # copies, so domain casing as typed/pasted is preserved in the
    # final domains.txt.
    LC_CLEANED="/tmp/add_domains_lc_cleaned_$$_${RANDOM}"
    LC_OUTPUT="/tmp/add_domains_lc_output_$$_${RANDOM}"
    tr '[:upper:]' '[:lower:]' < "$CLEANED" | sort -u > "$LC_CLEANED"
    tr '[:upper:]' '[:lower:]' < "$OUTPUT"  | sort -u > "$LC_OUTPUT"

    # Lines present in LC_CLEANED but not LC_OUTPUT = genuinely new
    NEW_LC="/tmp/add_domains_new_lc_$$_${RANDOM}"
    comm -23 "$LC_CLEANED" "$LC_OUTPUT" > "$NEW_LC"

    # Map back to original casing: keep only pasted lines whose
    # lowercased form appears in NEW_LC
    > "$DEDUPED"
    while IFS= read -r domain; do
        lc_domain=$(echo "$domain" | tr '[:upper:]' '[:lower:]')
        if grep -qxF "$lc_domain" "$NEW_LC" 2>/dev/null; then
            echo "$domain" >> "$DEDUPED"
        fi
    done < "$CLEANED"

    rm -f "$LC_CLEANED" "$LC_OUTPUT" "$NEW_LC"
    n_already_in_list=$(( n_unique_pasted - $(wc -l < "$DEDUPED") ))
else
    cp "$CLEANED" "$DEDUPED"
fi
n_after_list_dedup=$(wc -l < "$DEDUPED")

# ── Dedupe against the cache ────────────────────────────────────────
n_in_cache=0
FINAL="/tmp/add_domains_final_$$_${RANDOM}"
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

[ "$INPUT" = "-" ] && rm -f "$RAW"
rm -f "$CLEANED" "$DEDUPED" "$FINAL"

echo "── Add summary ──────────────────────────────"
echo "  Pasted:                  $n_pasted"
echo "  Unique in paste:         $n_unique_pasted"
echo "  Already in $OUTPUT:      $n_already_in_list"
echo "  Already cached/checked:  $n_in_cache"
echo "  NEW domains added:       $n_final"
echo "  → $OUTPUT now ready for ./pipeline.sh"
