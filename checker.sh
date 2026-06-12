#!/bin/bash
# checker.sh — parallel backlink checker
# Usage: ./checker.sh [-d domains.txt] [-p proxies.txt] [-j 5] [-r 3]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p reports

# ── Config ────────────────────────────────────────────────────────
DOMAINS_FILE="domains.txt"; PROXY_FILE="proxies.txt"
JOBS=5; MAX_RETRIES=3; RETRY_DELAY=2; TIMEOUT=10
export MAX_RETRIES RETRY_DELAY TIMEOUT

while getopts "d:p:j:r:" o; do case $o in
    d) DOMAINS_FILE="$OPTARG" ;; p) PROXY_FILE="$OPTARG" ;;
    j) JOBS="$OPTARG" ;;       r) MAX_RETRIES="$OPTARG" ;;
esac; done

ID="$(date +%s)"
export LOG="./reports/checker_${ID}.log"
export REPORT="./reports/backlinks_${ID}.csv"
export PROXY_FILE PROXY_CTR="/tmp/dhc_ctr_${ID}"
export PROXY_LCK="/tmp/dhc_plck_${ID}" RPT_LCK="/tmp/dhc_rlck_${ID}"

source lib.sh

# ── Validate ──────────────────────────────────────────────────────
[ -f "$DOMAINS_FILE" ]         || { err "$DOMAINS_FILE not found"; exit 1; }
[ -n "${DATAFORSEO_TOKEN:-}" ] || { err "DATAFORSEO_TOKEN not set"; exit 1; }
command -v jq &>/dev/null      || { err "jq required: apt install jq"; exit 1; }

trap 'rm -f "$PROXY_CTR" "$PROXY_LCK" "$RPT_LCK"' EXIT

# ── Init ──────────────────────────────────────────────────────────
PROXY_COUNT=$(proxy_init)
echo "domain,rank,backlinks,ref_domains,spam_score,status" > "$REPORT"
TOTAL=$(grep -c '\S' "$DOMAINS_FILE" || true)
log "Starting — $TOTAL domains, $JOBS workers"

# ── Worker ────────────────────────────────────────────────────────
worker() {
    local domain="$1"
    source lib.sh
    local proxy; proxy=$(proxy_get "$PROXY_COUNT")
    log "[$domain] proxy: ${proxy:-direct}"

    local raw; raw=$(api_backlinks "$domain" "$proxy")
    local dr bl rd spam
    IFS='|' read -r dr bl rd spam <<< "$raw"

    if [ "$dr" = "ERR" ]; then
        err "$domain failed"
        csv_write "$domain,ERR,ERR,ERR,ERR,FAILED"
    else
        echo -e "${G}${W}  *** $domain ***${N}  DR:$dr  BL:$bl  RD:$rd  Spam:${spam}%" >&2
        csv_write "$domain,$dr,$bl,$rd,$spam,OK"
    fi
}
export -f worker
export PROXY_COUNT DATAFORSEO_TOKEN

grep '\S' "$DOMAINS_FILE" | xargs -I{} -P"$JOBS" bash -c "worker '{}'"

# ── Summary ───────────────────────────────────────────────────────
OK=$(grep -c ',OK$' "$REPORT" || true)
FAIL=$(grep -c ',FAILED$' "$REPORT" || true)
echo "" >&2
ok "Done — $OK succeeded, $FAIL failed"
ok "Report: $REPORT"

if grep -q ',OK$' "$REPORT"; then
    echo "" >&2
    echo -e "${W}  Top domains by DR:${N}" >&2
    grep ',OK$' "$REPORT" | sort -t',' -k2 -rn | head -10 \
        | awk -F',' '{printf "  %-35s DR:%-5s BL:%-10s RD:%s\n",$1,$2,$3,$4}' >&2
fi
