#!/bin/bash
# pipeline.sh — 13-check domain analysis pipeline
# Checks: WHOIS → index → backlinks → wayback → niche → redirects →
#         anchors → spam domains → link ratio → cache →
#         foreign anchors → link velocity → IP diversity → composite score
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p reports

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
export RPT_LCK="/tmp/dhp_rlck_${ID}"

source lib.sh

[ -f "$DOMAINS_FILE" ]         || { err "$DOMAINS_FILE not found"; exit 1; }
[ -n "${DATAFORSEO_TOKEN:-}" ] || { err "DATAFORSEO_TOKEN not set"; exit 2; }
command -v jq    &>/dev/null   || { err "jq required"; exit 1; }
command -v whois &>/dev/null   || { err "whois required"; exit 1; }

trap 'rm -f "$FREE" "$RPT_LCK" "/tmp/dhp_valid_${ID}"' EXIT

# ── Domain validation ─────────────────────────────────────────────
VALID="/tmp/dhp_valid_${ID}"
n_valid=0; n_invalid=0
while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    [[ "$line" == \#* ]] && continue
    if [[ "$line" =~ ^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+$ ]]; then
        echo "$line" >> "$VALID"
        (( n_valid++ )) || true
    else
        warn "Skipping invalid: '${line}'"
        (( n_invalid++ )) || true
    fi
done < "$DOMAINS_FILE"
log "Loaded $n_valid valid domains ($n_invalid skipped)"
[ "$n_valid" -eq 0 ] && { err "No valid domains"; exit 1; }

# CSV header — all 13 checks + composite score
echo "domain,available,index_status,indexed_pages,rank,backlinks,ref_domains,spam_score,wb_first,wb_last,wb_age,wb_snaps,niche,niche_status,niche_changes,redirect_status,redirect_hops,anchor_flag,anchor_count,top_anchor,spam_rd_count,top_spam_domain,top_spam_score,spam_concentration,link_rd,link_bl,link_ratio,link_flag,cache_status,foreign_anchors,foreign_pct,foreign_flag,velocity_flag,velocity_max,velocity_spike_pct,ip_flag,ip_networks,ip_conc_pct,score,grade,score_flags,status" > "$REPORT"
> "$FREE"

TOTAL="$n_valid"; FREE_N=0; TAKEN_N=0

# ══ STAGE 1 — WHOIS ══════════════════════════════════════════════
echo -e "\n${W}══ STAGE 1 — Availability ($TOTAL domains) ══${N}" >&2
n=0
while IFS= read -r domain; do
    (( n++ )) || true
    echo -ne "  [$n/$TOTAL] $domain... " >&2
    reg=$(whois "$domain" 2>/dev/null | grep -i "^Registrar:" | head -1 || true)
    if [ -n "$reg" ]; then
        echo -e "${R}TAKEN${N}" >&2
        csv_write "$domain,TAKEN,N/A,0,N/A,N/A,N/A,N/A,N/A,N/A,N/A,0,N/A,N/A,0,N/A,0,N/A,0,N/A,0,N/A,0,N/A,0,0,0,N/A,N/A,0,0,N/A,N/A,0,0,N/A,0,0,0,N/A,N/A,TAKEN"
        (( TAKEN_N++ )) || true
    else
        echo -e "${G}FREE${N}" >&2
        echo "$domain" >> "$FREE"
        csv_write "$domain,FREE,~,0,0,0,0,0,~,~,~,0,~,~,0,~,0,~,0,~,0,~,0,~,0,0,0,~,~,0,0,~,~,0,0,~,0,0,0,~,~,PENDING"
        (( FREE_N++ )) || true
    fi
    sleep "$WHOIS_DELAY"
done < "$VALID"
log "Stage 1 — Free:$FREE_N Taken:$TAKEN_N"
[ "$FREE_N" -eq 0 ] && { warn "No free domains. Exiting."; exit 0; }

# ══ STAGES 2-13 — All checks + score ═════════════════════════════
export DATAFORSEO_TOKEN R G Y B W N

echo -e "\n${W}══ STAGES 2-13 — All checks ($FREE_N domains, $JOBS parallel) ══${N}" >&2

worker() {
    local domain="$1"
    source lib.sh
    echo -e "\n${W}  ▶ $domain${N}" >&2

    # ── All 13 checks ─────────────────────────────────────────────
    local idx_raw;  idx_raw=$(api_index "$domain")
    local bl_raw;   bl_raw=$(api_backlinks "$domain")
    local wb_raw;   wb_raw=$(api_wayback "$domain")
    local nc_raw;   nc_raw=$(api_niche "$domain")
    local rd_raw;   rd_raw=$(api_redirects "$domain")
    local anc_raw;  anc_raw=$(api_anchors "$domain")
    local spd_raw;  spd_raw=$(api_spam_domains "$domain")
    local tf_raw;   tf_raw=$(api_tf_cf "$domain")
    local cache;    cache=$(api_cache "$domain")
    local fa_raw;   fa_raw=$(api_foreign_anchors "$domain")
    local vel_raw;  vel_raw=$(api_link_velocity "$domain")
    local ip_raw;   ip_raw=$(api_ip_diversity "$domain")

    # ── Parse all results ─────────────────────────────────────────
    local idx_status idx_pages
    IFS='|' read -r idx_status idx_pages <<< "$idx_raw"

    local dr bl rd spam
    IFS='|' read -r dr bl rd spam <<< "$bl_raw"

    local wb_first wb_last wb_age wb_snaps
    IFS='|' read -r wb_first wb_last wb_age wb_snaps <<< "$wb_raw"

    local nc_status nc_changes nc_dominant
    IFS='|' read -r nc_status nc_changes nc_dominant <<< "$nc_raw"

    local redir_status redir_hops
    IFS='|' read -r redir_status redir_hops <<< "$rd_raw"

    local anc_flag anc_count top_anchor
    IFS='|' read -r anc_flag anc_count top_anchor <<< "$anc_raw"

    local spd_count top_spd top_spd_sc spd_conc
    IFS='|' read -r spd_count top_spd top_spd_sc spd_conc <<< "$spd_raw"

    local lrd lbl lratio lflag
    IFS='|' read -r lrd lbl lratio lflag <<< "$tf_raw"

    local fa_count fa_pct fa_flag
    IFS='|' read -r fa_count fa_pct fa_flag <<< "$fa_raw"

    local vel_flag vel_max vel_spike_pct
    IFS='|' read -r vel_flag vel_max vel_spike_pct <<< "$vel_raw"

    local ip_flag ip_networks ip_conc_pct
    IFS='|' read -r ip_flag ip_networks ip_conc_pct <<< "$ip_raw"

    # ── Composite score ───────────────────────────────────────────
    local score_raw score grade score_flags
    score_raw=$(calculate_score \
        "$idx_status" "$dr" "$bl" "$spam" \
        "$nc_status" "$redir_status" "$anc_flag" \
        "$lflag" "$cache" "$wb_age" \
        "$spd_count" "$vel_flag" "$fa_flag" "$ip_flag")
    IFS='|' read -r score grade score_flags <<< "$score_raw"

    local status="OK"
    [ "$dr" = "ERR" ] && status="FAILED"

    # ── Color-coded display ───────────────────────────────────────
    local ic="$Y"; [ "$idx_status" = "CLEAN" ] && ic="$G"; [ "$idx_status" = "SPAM" ] && ic="$R"
    local nc="$G"; [ "$nc_status" = "INCONSISTENT" ] && nc="$Y"; [ "$nc_status" = "UNSTABLE" ] && nc="$R"
    local rc="$G"; [ "$redir_status" != "OK" ] && rc="$R"
    local cc="$G"; [ "$cache" != "CACHED" ] && cc="$Y"
    local vc="$G"; [ "$vel_flag" != "OK" ] && vc="$R"
    local fc="$G"; [ "$fa_flag" != "OK" ] && fc="$Y"
    local ipc="$G"; [ "$ip_flag" != "OK" ] && ipc="$Y"

    # Score color
    local sc_c="$R"
    [ "$score" -ge 45 ] && sc_c="$Y"
    [ "$score" -ge 60 ] && sc_c="$G"

    echo -e "  ${sc_c}${W}SCORE: ${score}/100 (${grade})${N}  ${score_flags}" >&2
    echo -e "  Index:      ${ic}${idx_status}${N} (${idx_pages}p)" >&2
    echo -e "  Backlinks:  DR:${W}${dr}${N}  BL:${W}${bl}${N}  RD:${W}${rd}${N}  Spam:${spam}%" >&2
    echo -e "  Wayback:    Age:${W}${wb_age}y${N}  First:${wb_first}  Last:${wb_last}  Snaps:${wb_snaps}" >&2
    echo -e "  Niche:      ${nc}${nc_status}${N} — ${nc_dominant} (${nc_changes} changes)" >&2
    echo -e "  Redirect:   ${rc}${redir_status}${N} (${redir_hops} hops)" >&2
    echo -e "  Anchors:    ${anc_flag}  ${anc_count} unique  Top:\"${top_anchor}\"" >&2
    echo -e "  Spam RDs:   ${spd_count} spammy  Top:${top_spd} (${top_spd_sc}%)  ${spd_conc}" >&2
    echo -e "  Link ratio: ${lratio} links/domain  ${lflag}" >&2
    echo -e "  Cache:      ${cc}${cache}${N}" >&2
    echo -e "  Foreign:    ${fc}${fa_flag}${N}  ${fa_count} anchors (${fa_pct}%)" >&2
    echo -e "  Velocity:   ${vc}${vel_flag}${N}  max month:${vel_max}  spike:${vel_spike_pct}%" >&2
    echo -e "  IP Diversity:${ipc}${ip_flag}${N}  networks:${ip_networks}  top conc:${ip_conc_pct}%" >&2
    echo "" >&2

    csv_update "$domain" \
        "${domain},FREE,${idx_status},${idx_pages},${dr},${bl},${rd},${spam},${wb_first},${wb_last},${wb_age},${wb_snaps},${nc_dominant},${nc_status},${nc_changes},${redir_status},${redir_hops},${anc_flag},${anc_count},${top_anchor},${spd_count},${top_spd},${top_spd_sc},${spd_conc},${lrd},${lbl},${lratio},${lflag},${cache},${fa_count},${fa_pct},${fa_flag},${vel_flag},${vel_max},${vel_spike_pct},${ip_flag},${ip_networks},${ip_conc_pct},${score},${grade},${score_flags},${status}"
}

export -f worker
grep '\S' "$FREE" | xargs -n 1 -P "$JOBS" bash -c 'worker "$1"' _
log "All checks complete"

# ══ FINAL REPORT ══════════════════════════════════════════════════
OK=$(grep -c      ',OK$'             "$REPORT" || true)
FAIL=$(grep -c    ',FAILED$'        "$REPORT" || true)
CLEAN=$(grep -c   ',CLEAN,'         "$REPORT" || true)
NOIDX=$(grep -c   ',NOT_INDEXED,'   "$REPORT" || true)
SPAM=$(grep -c    ',SPAM,'          "$REPORT" || true)
CACHED=$(grep -c  ',CACHED,'        "$REPORT" || true)
GRADE_A=$(awk -F',' '$40=="A"' "$REPORT" | wc -l || true)
GRADE_B=$(awk -F',' '$40=="B"' "$REPORT" | wc -l || true)
SPIKES=$(grep -cE 'SPIKE'           "$REPORT" || true)
FOREIGN=$(grep -c 'HIGH_FOREIGN'    "$REPORT" || true)

echo -e "\n${W}══ FINAL REPORT ══${N}" >&2
printf "  %-24s %s\n"                             "Checked:"         "$TOTAL"    >&2
printf "  %-24s ${G}%s${N}  Taken: ${R}%s${N}\n" "Free:"            "$FREE_N"   "$TAKEN_N" >&2
printf "  %-24s ${G}%s${N}\n"                     "Grade A (75+):"   "$GRADE_A"  >&2
printf "  %-24s ${G}%s${N}\n"                     "Grade B (60+):"   "$GRADE_B"  >&2
printf "  %-24s ${G}%s${N}\n"                     "Indexed clean:"   "$CLEAN"    >&2
printf "  %-24s ${Y}%s${N}\n"                     "Not indexed:"     "$NOIDX"    >&2
printf "  %-24s ${R}%s${N}\n"                     "Spam content:"    "$SPAM"     >&2
printf "  %-24s ${G}%s${N}\n"                     "Google cached:"   "$CACHED"   >&2
printf "  %-24s ${R}%s${N}\n"                     "Link spikes:"     "$SPIKES"   >&2
printf "  %-24s ${R}%s${N}\n"                     "Foreign spam:"    "$FOREIGN"  >&2
printf "  %-24s ${G}%s${N}  Failed: ${R}%s${N}\n" "Backlinks OK:"   "$OK"       "$FAIL" >&2

echo -e "\n  ${W}Top free domains by SCORE:${N}" >&2
grep ',FREE,' "$REPORT" | grep -v ',TAKEN,' \
    | sort -t',' -k39 -rn | head -10 \
    | awk -F',' '{printf "  %-32s Score:%-5s Grade:%-3s DR:%-5s Index:%-14s\n",$1,$39,$40,$5,$3}' >&2

echo "" >&2
ok "Report: $REPORT"
ok "Log:    $LOG"
echo "" >&2
