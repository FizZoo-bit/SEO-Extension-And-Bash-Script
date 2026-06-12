#!/bin/bash
# pipeline.sh — WHOIS → index check → backlinks
# Usage: ./pipeline.sh [-d domains.txt] [-j 5]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p reports

# ── Config ────────────────────────────────────────────────────────
DOMAINS_FILE="domains.txt"; JOBS=5
WHOIS_DELAY=1; MAX_RETRIES=3; RETRY_DELAY=2; TIMEOUT=15
export MAX_RETRIES RETRY_DELAY TIMEOUT

while getopts "d:j:" o; do case $o in
    d) DOMAINS_FILE="$OPTARG" ;; j) JOBS="$OPTARG" ;;
esac; done

ID="$(date +%s)"
FREE="/tmp/dhp_free_${ID}"
export LOG="./reports/pipeline_${ID}.log"
export REPORT="./reports/pipeline_report_${ID}.csv"
export PROXY_FILE="proxies.txt"
export PROXY_CTR="/tmp/dhp_ctr_${ID}"
export PROXY_LCK="/tmp/dhp_plck_${ID}"
export RPT_LCK="/tmp/dhp_rlck_${ID}"

source lib.sh

# ── Validate ──────────────────────────────────────────────────────
[ -f "$DOMAINS_FILE" ]         || { err "$DOMAINS_FILE not found"; exit 1; }
[ -n "${DATAFORSEO_TOKEN:-}" ] || { err "DATAFORSEO_TOKEN not set"; exit 1; }
command -v jq    &>/dev/null   || { err "jq required"; exit 1; }
command -v whois &>/dev/null   || { err "whois required"; exit 1; }

trap 'rm -f "$FREE" "$PROXY_CTR" "$PROXY_LCK" "$RPT_LCK"' EXIT

echo "domain,available,index_status,indexed_pages,rank,backlinks,ref_domains,spam_score,status" > "$REPORT"
> "$FREE"

TOTAL=$(grep -c '\S' "$DOMAINS_FILE" || true)
FREE_N=0; TAKEN_N=0

# ════════════════════════════════════════════════════════════════
# STAGE 1 — WHOIS
# ════════════════════════════════════════════════════════════════
echo -e "\n${W}══ STAGE 1 — Availability ($TOTAL domains) ══${N}" >&2
n=0
while IFS= read -r domain; do
    [ -z "$domain" ] || [[ "$domain" == \#* ]] && continue
    (( n++ )) || true
    echo -ne "  [$n/$TOTAL] $domain... " >&2
    reg=$(whois "$domain" 2>/dev/null | grep -i "^Registrar:" | head -1 || true)
    if [ -n "$reg" ]; then
        echo -e "${R}TAKEN${N}" >&2
        csv_write "$domain,TAKEN,N/A,0,N/A,N/A,N/A,N/A,TAKEN"
        (( TAKEN_N++ )) || true
    else
        echo -e "${G}FREE${N}" >&2
        echo "$domain" >> "$FREE"
        csv_write "$domain,FREE,PENDING,0,,,,,PENDING"
        (( FREE_N++ )) || true
    fi
    sleep "$WHOIS_DELAY"
done < "$DOMAINS_FILE"
log "Stage 1 done — Free:$FREE_N Taken:$TAKEN_N"

[ "$FREE_N" -eq 0 ] && { warn "No free domains. Exiting."; exit 0; }

# ════════════════════════════════════════════════════════════════
# STAGE 2 — Index check + Stage 3 — Backlinks (combined worker)
# ════════════════════════════════════════════════════════════════
# Running both checks in one worker saves one xargs spawn cycle
# and keeps all data for a domain processed together.

PROXY_COUNT=$(proxy_init)
export PROXY_COUNT DATAFORSEO_TOKEN

echo -e "\n${W}══ STAGE 2+3 — Index & Backlinks ($FREE_N domains) ══${N}" >&2

worker() {
    local domain="$1"
    source lib.sh

    # Index check
    local idx_raw; idx_raw=$(api_index "$domain")
    local idx_status idx_pages
    IFS='|' read -r idx_status idx_pages <<< "$idx_raw"

    # Backlink check
    local proxy; proxy=$(proxy_get "$PROXY_COUNT")
    local bl_raw; bl_raw=$(api_backlinks "$domain" "$proxy")
    local dr bl rd spam
    IFS='|' read -r dr bl rd spam <<< "$bl_raw"

    # Status
    local status="OK"; [ "$dr" = "ERR" ] && status="FAILED"

    # Display
    local idx_color="$Y"
    [ "$idx_status" = "CLEAN" ]       && idx_color="$G"
    [ "$idx_status" = "SPAM" ]        && idx_color="$R"
    [ "$idx_status" = "NOT_INDEXED" ] && idx_color="$Y"
    echo -e "${G}${W}  *** $domain ***${N}" >&2
    echo -e "  Index: ${idx_color}${idx_status}${N} (${idx_pages}p)  DR:${dr}  BL:${bl}  RD:${rd}  Spam:${spam}%" >&2
    echo "" >&2

    # Update CSV — replace PENDING row
    csv_update \
        "^${domain},FREE,PENDING,0,,,,,PENDING" \
        "${domain},FREE,${idx_status},${idx_pages},${dr},${bl},${rd},${spam},${status}"
}

export -f worker
grep '\S' "$FREE" | xargs -I{} -P"$JOBS" bash -c "worker '{}'"
log "Stages 2+3 done"

# ════════════════════════════════════════════════════════════════
# FINAL REPORT
# ════════════════════════════════════════════════════════════════
OK=$(grep -c ',OK$'     "$REPORT" || true)
FAIL=$(grep -c ',FAILED$' "$REPORT" || true)
CLEAN=$(grep -c ',CLEAN,' "$REPORT" || true)
NOIDX=$(grep -c ',NOT_INDEXED,' "$REPORT" || true)
SPAM=$(grep -c ',SPAM,' "$REPORT" || true)

echo "" >&2
echo -e "${W}══ FINAL REPORT ══${N}" >&2
echo -e "  Checked:       $TOTAL" >&2
echo -e "  Free:          ${G}$FREE_N${N}  Taken: ${R}$TAKEN_N${N}" >&2
echo -e "  Indexed clean: ${G}$CLEAN${N}  Not indexed: ${Y}$NOIDX${N}  Spam: ${R}$SPAM${N}" >&2
echo -e "  Backlinks OK:  ${G}$OK${N}  Failed: ${R}$FAIL${N}" >&2

if grep -q ',OK$' "$REPORT" 2>/dev/null; then
    echo "" >&2
    echo -e "${W}  Top free domains by DR:${N}" >&2
    grep ',FREE,' "$REPORT" | grep ',OK$' \
        | sort -t',' -k5 -rn | head -10 \
        | awk -F',' '{printf "  %-35s DR:%-5s BL:%-10s RD:%-8s Index:%s\n",$1,$5,$6,$7,$3}' >&2
fi

echo "" >&2
ok "Report: $REPORT"
ok "Log:    $LOG"
