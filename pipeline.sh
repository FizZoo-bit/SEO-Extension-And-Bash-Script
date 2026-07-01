#!/bin/bash
# pipeline.sh — 12-check domain analysis pipeline
# Stage 1 (WHOIS) runs WHOIS_JOBS lookups in parallel (default 3).
# Stages 2-13 run JOBS domains in parallel (default 5).
# Checks: WHOIS → index → backlinks → wayback → niche → redirects →
#         anchors → spam domains → link ratio →
#         foreign anchors → link velocity → IP diversity → composite score
# (Google cache check removed — Google retired the public cache
#  feature in Sept 2024; see lib.sh for full explanation)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p reports

DOMAINS_FILE="domains.txt"; JOBS=5; WHOIS_JOBS=3
WHOIS_DELAY=1; MAX_RETRIES=3; RETRY_DELAY=2; TIMEOUT=15
USE_CACHE=1; CACHE_MAX_AGE_DAYS=7; EARLY_EXIT_ENABLED=1
export MAX_RETRIES RETRY_DELAY TIMEOUT

while getopts "d:j:w:a:ce:" o; do case $o in
    d) DOMAINS_FILE="$OPTARG" ;; j) JOBS="$OPTARG" ;; w) WHOIS_JOBS="$OPTARG" ;;
    a) CACHE_MAX_AGE_DAYS="$OPTARG" ;; c) USE_CACHE=0 ;; e) EARLY_EXIT_ENABLED="$OPTARG" ;;
esac; done
export EARLY_EXIT_ENABLED

ID="$(date +%s)"
FREE="/tmp/dhp_free_${ID}"
export LOG="./reports/pipeline_${ID}.log"
export REPORT="./reports/pipeline_report_${ID}.csv"
export RPT_LCK="/tmp/dhp_rlck_${ID}"
export ABORT_FLAG="/tmp/dhp_abort_${ID}"
export CACHE_LCK="/tmp/dhp_cache_lock"
export CACHE_MAX_AGE_DAYS
if [ "$USE_CACHE" -eq 1 ]; then
    export CACHE_DB="./reports/domain_cache.sqlite3"
else
    export CACHE_DB=""
fi

source lib.sh
cache_init

[ -f "$DOMAINS_FILE" ]         || { err "$DOMAINS_FILE not found"; exit 1; }
[ -n "${DATAFORSEO_TOKEN:-}" ] || { err "DATAFORSEO_TOKEN not set"; exit 2; }
command -v jq    &>/dev/null   || { err "jq required"; exit 1; }
command -v whois &>/dev/null   || { err "whois required"; exit 1; }

trap 'rm -f "$FREE" "$RPT_LCK" "$ABORT_FLAG" "/tmp/dhp_valid_${ID}" "/tmp/dhp_whois_taken_${ID}" "/tmp/dhp_whois_freecount_${ID}" "/tmp/dhp_fresh_${ID}" "/tmp/dhp_transient_${ID}" "/tmp/dhp_transient_lock_${ID}"' EXIT

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

# CSV header — 12 checks + composite score
echo "domain,available,index_status,indexed_pages,rank,backlinks,ref_domains,spam_score,wb_first,wb_last,wb_age,wb_snaps,niche,niche_status,niche_changes,redirect_status,redirect_hops,anchor_flag,anchor_count,top_anchor,spam_rd_count,top_spam_domain,top_spam_score,spam_concentration,link_rd,link_bl,link_ratio,link_flag,foreign_anchors,foreign_pct,foreign_flag,velocity_flag,velocity_max,velocity_spike_pct,ip_flag,ip_networks,ip_conc_pct,robots_status,sitemap_status,sitemap_urls,content_quality,dbl_status,host_flag,authority,spam_risk,link_profile,stability,score,grade,score_flags,status" > "$REPORT"
> "$FREE"

# ── Cache lookup ──────────────────────────────────────────────────
# Check every valid domain against the persistent cache BEFORE WHOIS
# or any paid API call. A fresh hit gets written straight to the CSV
# and is removed from the list that Stage 1/2 will actually process —
# this is the only place caching saves real time/cost, since it skips
# work entirely rather than just speeding up work we'd do anyway.
FRESH="/tmp/dhp_fresh_${ID}"
> "$FRESH"
n_cached=0
if [ -n "${CACHE_DB:-}" ]; then
    while IFS= read -r domain; do
        cached_row=$(cache_get "$domain" || true)
        if [ -n "$cached_row" ]; then
            csv_write "$cached_row"
            (( n_cached++ )) || true
        else
            echo "$domain" >> "$FRESH"
        fi
    done < "$VALID"
    [ "$n_cached" -gt 0 ] && log "Cache — $n_cached domain(s) served from cache (max age ${CACHE_MAX_AGE_DAYS}d), skipping WHOIS+API for these"
    VALID="$FRESH"
    n_valid=$(wc -l < "$VALID" 2>/dev/null || echo 0)
fi

TOTAL="$n_valid"

# ══ STAGE 1 — WHOIS (parallel) ═══════════════════════════════════
# Previously fully sequential with a fixed sleep after every domain —
# for 50 domains at WHOIS_DELAY=1 that's 50+ seconds spent purely
# sleeping, before counting actual WHOIS round-trip time at all.
# Now runs WHOIS_JOBS lookups concurrently via the same xargs -P
# pattern Stage 2 already uses. Most registrars rate-limit per source
# IP rather than globally, so a modest parallelism of 3 is safe while
# still cutting total wait time dramatically.
#
# Child processes can't write back into this shell's FREE_N/TAKEN_N
# variables, so each worker appends its own result to a small temp
# file instead, and we derive the final counts from those files once
# all workers finish — same principle as the CSV locking, just simpler
# since these are tiny single-line writes.
echo -e "\n${W}══ STAGE 1 — Availability ($TOTAL domains) ══${N}" >&2
WHOIS_TAKEN="/tmp/dhp_whois_taken_${ID}"
WHOIS_FREE_COUNT="/tmp/dhp_whois_freecount_${ID}"
> "$WHOIS_TAKEN"; > "$WHOIS_FREE_COUNT"
export REPORT RPT_LCK FREE WHOIS_TAKEN WHOIS_FREE_COUNT R G N WHOIS_DELAY

whois_worker() {
    local domain="$1"
    source lib.sh
    local reg
    reg=$(whois "$domain" 2>/dev/null | grep -i "^Registrar:" | head -1 || true)
    if [ -n "$reg" ]; then
        echo -e "  ${R}TAKEN${N}  $domain" >&2
        local taken_row="$domain,TAKEN,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,TAKEN"
        csv_write "$taken_row"
        cache_set "$domain" "$taken_row"
        echo "$domain" >> "$WHOIS_TAKEN"
    else
        echo -e "  ${G}FREE${N}   $domain" >&2
        echo "$domain" >> "$FREE"
        csv_write "$domain,FREE,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,~,PENDING"
        echo "1" >> "$WHOIS_FREE_COUNT"
    fi
    # Still a small per-worker delay to stay polite to registrars —
    # parallelism across WHOIS_JOBS workers already gives most of the
    # speedup, this just avoids any single worker hammering a registrar
    # back-to-back with zero pause.
    sleep "$WHOIS_DELAY"
}
export -f whois_worker

cat "$VALID" | xargs -n 1 -P "$WHOIS_JOBS" bash -c 'whois_worker "$1"' _

TAKEN_N=$(wc -l < "$WHOIS_TAKEN" 2>/dev/null || echo 0)
FREE_N=$(wc -l < "$WHOIS_FREE_COUNT" 2>/dev/null || echo 0)
rm -f "$WHOIS_TAKEN" "$WHOIS_FREE_COUNT"

log "Stage 1 — Free:$FREE_N Taken:$TAKEN_N"
[ "$FREE_N" -eq 0 ] && { warn "No free domains. Exiting."; exit 0; }

# ══ STAGES 2-13 — All checks + score ═════════════════════════════
export DATAFORSEO_TOKEN R G Y B W N

echo -e "\n${W}══ STAGES 2-13 — All checks ($FREE_N domains, $JOBS parallel) ══${N}" >&2

worker() {
    local domain="$1"
    source lib.sh

    # All terminal output for this worker is accumulated here and
    # printed with ONE echo at the end of the function, instead of
    # ~20 separate echo calls scattered across a function that takes
    # several seconds to run. With JOBS workers writing to the same
    # stderr concurrently, separate echo calls have no ordering
    # guarantee relative to each other — a slow worker's banner line
    # can print, then a FASTER sibling's entire result block can print
    # before the slow worker's own result block is ready, making it
    # LOOK like one domain's banner is followed by a different
    # domain's data. The underlying CSV data is unaffected either way
    # (each worker still calls csv_update with its own correct
    # domain+row), but the terminal becomes actively misleading and
    # wastes real debugging time chasing a data bug that doesn't
    # exist. Buffering into one atomic-ish write per worker doesn't
    # eliminate concurrency, but keeps each worker's own banner and
    # result block visually together.
    local out=""

    # If a sibling worker already hit a fatal error (bad credentials,
    # no balance, no subscription), stop immediately rather than making
    # more API calls that will fail identically and waste time/quota.
    if check_abort; then
        echo -e "  ${R}⊘ Skipping ${domain} — pipeline aborted: $(cat "$ABORT_FLAG" 2>/dev/null)${N}" >&2
        return 0
    fi

    out+="\n${W}  ▶ $domain${N}\n"

    # ── Cheap checks first (free or near-free) — these decide whether
    # paid checks are worth running at all. Fired in PARALLEL via
    # background jobs (same pattern already used for Wayback snapshot
    # fetching) since all 5 are independent of each other — there's no
    # reason api_index, api_wayback_and_niche, api_robots_sitemap,
    # api_spamhaus_dbl, and api_hosting_footprint should run one after
    # another when none of them depend on another's result. This was
    # costing ~5 sequential round-trips per domain regardless of
    # whether the domain ultimately hits the early-exit path or not.
    # ──────────────────────────────────────────────────────────────
    local cheap_tmpdir="/tmp/dhp_cheap_${ID}_$$_${RANDOM}"
    mkdir -p "$cheap_tmpdir"
    ( api_index "$domain"             > "${cheap_tmpdir}/idx.txt" )  &
    ( api_wayback_and_niche "$domain" > "${cheap_tmpdir}/wn.txt" )   &
    ( api_robots_sitemap "$domain"    > "${cheap_tmpdir}/rs.txt" )   &
    ( api_spamhaus_dbl "$domain"      > "${cheap_tmpdir}/dbl.txt" )  &
    ( api_hosting_footprint "$domain" > "${cheap_tmpdir}/host.txt" ) &
    wait

    local idx_raw;  idx_raw=$(cat "${cheap_tmpdir}/idx.txt" 2>/dev/null)
    local wn_raw;   wn_raw=$(cat "${cheap_tmpdir}/wn.txt" 2>/dev/null)
    local rs_raw;   rs_raw=$(cat "${cheap_tmpdir}/rs.txt" 2>/dev/null)
    local dbl_raw;  dbl_raw=$(cat "${cheap_tmpdir}/dbl.txt" 2>/dev/null)
    local host_raw; host_raw=$(cat "${cheap_tmpdir}/host.txt" 2>/dev/null)
    rm -rf "$cheap_tmpdir"

    local idx_status idx_pages
    IFS='|' read -r idx_status idx_pages <<< "$idx_raw"
    local wb_first wb_last wb_age wb_snaps nc_status nc_changes nc_dominant content_quality
    IFS='|' read -r wb_first wb_last wb_age wb_snaps nc_status nc_changes nc_dominant content_quality <<< "$wn_raw"
    local robots_status sitemap_status sitemap_urls
    IFS='|' read -r robots_status sitemap_status sitemap_urls <<< "$rs_raw"
    local dbl_status dbl_code
    IFS='|' read -r dbl_status dbl_code <<< "$dbl_raw"
    local host_flag host_ns
    IFS='|' read -r host_flag host_ns <<< "$host_raw"

    # ── Early-exit filter (weighted, not a single binary gate) ────
    # The old version skipped paid checks purely on "zero Wayback
    # snapshots AND not indexed" — but we're now computing robots.txt/
    # sitemap.xml/Spamhaus signals for every domain in parallel
    # regardless, and were simply discarding that information for
    # skipped domains instead of feeding it back into the decision.
    # A domain with zero Wayback history but a real sitemap.xml
    # listing dozens of URLs is a meaningfully different case than one
    # with nothing at all — "never crawled by the Internet Archive"
    # is not the same claim as "definitely has no real content."
    #
    # cheap_signal_score: starts at 0, any positive free signal adds
    # to it. Only skip if it stays at 0 (genuinely nothing going for
    # this domain across every free check we have). This still skips
    # the vast majority of junk domains exactly as before — it just
    # stops incorrectly skipping the rare domain that has real
    # structure (sitemap, working robots.txt) but happened to dodge
    # Wayback's crawler and Google's index.
    local cheap_signal_score=0
    [ "$idx_status" = "CLEAN" ]                                  && (( cheap_signal_score += 3 )) || true
    [ "${wb_snaps:-0}" -gt 0 ] 2>/dev/null                       && (( cheap_signal_score += 2 )) || true
    [ "$sitemap_status" = "OK" ] || [ "$sitemap_status" = "SITEMAP_INDEX" ] && (( cheap_signal_score += 1 )) || true
    [ "${sitemap_urls:-0}" -gt 5 ] 2>/dev/null                   && (( cheap_signal_score += 1 )) || true
    [ "$robots_status" = "OK" ]                                  && (( cheap_signal_score += 1 )) || true

    if [ "${EARLY_EXIT_ENABLED:-1}" = "1" ] && [ "$cheap_signal_score" -eq 0 ]; then
        out+="  ${Y}⊘ SKIPPED_CHEAP_FILTER${N} — no positive signal across any free check, skipping paid checks\n"
        out+="  Index:      ${idx_status} (${idx_pages}p)\n"
        out+="  Wayback:    Age:N/Ay  Snaps:0\n"
        out+="  Robots/Sitemap: ${robots_status} / ${sitemap_status} (${sitemap_urls} URLs)\n"
        out+="  Spamhaus:   ${dbl_status}   Hosting: ${host_flag} (${host_ns})\n"
        out+="\n"
        echo -e "$out" >&2
        local skip_row="${domain},FREE,${idx_status},${idx_pages},0,0,0,0,${wb_first},${wb_last},${wb_age},${wb_snaps},${nc_dominant},${nc_status},${nc_changes},N/A,N/A,N/A,0,N/A,0,N/A,0,N/A,0,0,0,N/A,0,0,N/A,N/A,0,0,N/A,0,0,${robots_status},${sitemap_status},${sitemap_urls},${content_quality},${dbl_status},${host_flag},N/A,N/A,N/A,N/A,N/A,N/A,SKIPPED_CHEAP_FILTER,SKIPPED_CHEAP_FILTER"
        csv_update "$domain" "$skip_row"
        return 0
    fi

    # ── 5 paid API calls — only reached if the domain passed the
    # cheap filter above ──────────────────────────────────────────
    local bl_raw;   bl_raw=$(api_backlinks_full "$domain")
    local rd_raw;   rd_raw=$(api_redirects "$domain")
    local anc_raw;  anc_raw=$(api_anchors_full "$domain")
    local spd_raw;  spd_raw=$(api_spam_domains "$domain")
    local vel_raw;  vel_raw=$(api_link_velocity "$domain")
    local ip_raw;   ip_raw=$(api_ip_diversity "$domain")

    # ── Parse paid results ───────────────────────────────────────
    local dr bl rd spam lrd lbl lratio lflag
    IFS='|' read -r dr bl rd spam lrd lbl lratio lflag <<< "$bl_raw"

    local redir_status redir_hops
    IFS='|' read -r redir_status redir_hops <<< "$rd_raw"

    local anc_flag anc_count top_anchor fa_count fa_pct fa_flag
    IFS='|' read -r anc_flag anc_count top_anchor fa_count fa_pct fa_flag <<< "$anc_raw"

    local spd_count top_spd top_spd_sc spd_conc
    IFS='|' read -r spd_count top_spd top_spd_sc spd_conc <<< "$spd_raw"

    local vel_flag vel_max vel_spike_pct
    IFS='|' read -r vel_flag vel_max vel_spike_pct <<< "$vel_raw"

    local ip_flag ip_networks ip_conc_pct
    IFS='|' read -r ip_flag ip_networks ip_conc_pct <<< "$ip_raw"

    # ── Composite score (cache_status param removed — feature gone) ─
    local score_raw score grade score_flags
    score_raw=$(calculate_score \
        "$idx_status" "$dr" "$bl" "$spam" \
        "$nc_status" "$redir_status" "$anc_flag" \
        "$lflag" "$wb_age" \
        "$spd_count" "$vel_flag" "$fa_flag" "$ip_flag" "$domain")
    IFS='|' read -r score grade score_flags authority spam_risk link_profile stability <<< "$score_raw"
    # Defense-in-depth: strip any stray commas from score_flags before
    # it enters the CSV. The internal separator is ';' by design, but
    # this guards against any future flag value accidentally containing
    # a literal comma, which would silently shift every column after it.
    score_flags=$(echo "$score_flags" | tr ',' ';')

    local status="OK"
    [ "$dr" = "ERR" ] && status="FAILED"

    # ── Color-coded display ───────────────────────────────────────
    local ic="$Y"; [ "$idx_status" = "CLEAN" ] && ic="$G"; [ "$idx_status" = "SPAM" ] && ic="$R"
    local nc="$G"; [ "$nc_status" = "INCONSISTENT" ] && nc="$Y"; [ "$nc_status" = "UNSTABLE" ] && nc="$R"
    local rc="$G"; [ "$redir_status" != "OK" ] && rc="$R"
    local vc="$G"; [ "$vel_flag" != "OK" ] && vc="$R"
    local fc="$G"; [ "$fa_flag" != "OK" ] && fc="$Y"
    local ipc="$G"; [ "$ip_flag" != "OK" ] && ipc="$Y"
    local rsc="$G"; [ "$robots_status" = "BLOCKS_ALL" ] && rsc="$R"
    local dblc="$G"; [[ "$dbl_status" == LISTED_* ]] && dblc="$R"
    local cqc="$G"; [ "$content_quality" = "PARKED_HISTORY" ] && cqc="$R"; [ "$content_quality" = "PARTIAL_PARKED" ] && cqc="$Y"
    local hostc="$G"; [ "$host_flag" = "DISPOSABLE_DNS" ] && hostc="$Y"

    local sc_c="$R"
    [ "$score" -ge 45 ] && sc_c="$Y"
    [ "$score" -ge 60 ] && sc_c="$G"

    out+="  ${sc_c}${W}SCORE: ${score}/100 (${grade})${N}  ${score_flags}\n"
    out+="  Index:      ${ic}${idx_status}${N} (${idx_pages}p)\n"
    out+="  Backlinks:  DR:${W}${dr}${N}  BL:${W}${bl}${N}  RD:${W}${rd}${N}  Spam:${spam}%\n"
    out+="  Wayback:    Age:${W}${wb_age}y${N}  First:${wb_first}  Last:${wb_last}  Snaps:${wb_snaps}  Content:${cqc}${content_quality}${N}\n"
    out+="  Robots/Sitemap: ${rsc}${robots_status}${N} / ${sitemap_status} (${sitemap_urls} URLs)\n"
    out+="  Spamhaus:   ${dblc}${dbl_status}${N}   Hosting: ${hostc}${host_flag}${N} (${host_ns})\n"
    out+="  Niche:      ${nc}${nc_status}${N} — ${nc_dominant} (${nc_changes} changes)\n"
    out+="  Redirect:   ${rc}${redir_status}${N} (${redir_hops} hops)\n"
    out+="  Anchors:    ${anc_flag}  ${anc_count} unique  Top:\"${top_anchor}\"\n"
    out+="  Spam RDs:   ${spd_count} spammy  Top:${top_spd} (${top_spd_sc}%)  ${spd_conc}\n"
    out+="  Link ratio: ${lratio} links/domain  ${lflag}\n"
    out+="  Foreign:    ${fc}${fa_flag}${N}  ${fa_count} anchors (${fa_pct}%)\n"
    out+="  Velocity:   ${vc}${vel_flag}${N}  max month:${vel_max}  spike:${vel_spike_pct}%\n"
    out+="  IP Diversity:${ipc}${ip_flag}${N}  networks:${ip_networks}  top conc:${ip_conc_pct}%\n"
    out+="\n"
    echo -e "$out" >&2

    local full_row="${domain},FREE,${idx_status},${idx_pages},${dr},${bl},${rd},${spam},${wb_first},${wb_last},${wb_age},${wb_snaps},${nc_dominant},${nc_status},${nc_changes},${redir_status},${redir_hops},${anc_flag},${anc_count},${top_anchor},${spd_count},${top_spd},${top_spd_sc},${spd_conc},${lrd},${lbl},${lratio},${lflag},${fa_count},${fa_pct},${fa_flag},${vel_flag},${vel_max},${vel_spike_pct},${ip_flag},${ip_networks},${ip_conc_pct},${robots_status},${sitemap_status},${sitemap_urls},${content_quality},${dbl_status},${host_flag},${authority},${spam_risk},${link_profile},${stability},${score},${grade},${score_flags},${status}"
    csv_update "$domain" "$full_row"

    # Only cache clean, fully-successful checks — never cache a row
    # that failed or hit an error, since we want the NEXT run to retry
    # those rather than serve a stale failure for CACHE_MAX_AGE_DAYS.
    if [ "$status" = "OK" ]; then
        cache_set "$domain" "$full_row"
        cache_record_history "$domain" "$score" "$grade" "$authority" "$spam_risk" "$link_profile" "$stability"
    fi
}

export -f worker

# ── Adaptive parallelism ──────────────────────────────────────────
# Fixed JOBS=5 is a reasonable default, but DataForSEO doesn't publish
# a hard concurrency limit we can read up front. Rather than guess once
# and hope, process domains in chunks and watch for transient (rate-
# limit-style) errors between chunks. A burst of them means we're
# pushing harder than the API wants right now — scale JOBS down for
# the remaining chunks. We never scale back up mid-run (keeps behavior
# predictable instead of oscillating); the next run starts fresh at
# the configured default.
export TRANSIENT_COUNTER="/tmp/dhp_transient_${ID}"
export TRANSIENT_LCK="/tmp/dhp_transient_lock_${ID}"
> "$TRANSIENT_COUNTER"

CHUNK_SIZE=$(( JOBS * 3 ))   # a few rounds of full parallelism per chunk
mapfile -t all_free < <(grep '\S' "$FREE")
total_free=${#all_free[@]}
idx=0
current_jobs="$JOBS"

while [ "$idx" -lt "$total_free" ]; do
    chunk=("${all_free[@]:idx:CHUNK_SIZE}")
    printf '%s\n' "${chunk[@]}" | xargs -n 1 -P "$current_jobs" bash -c 'worker "$1"' _

    check_abort && break

    transient_hits=$(wc -l < "$TRANSIENT_COUNTER" 2>/dev/null || echo 0)
    if [ "$transient_hits" -ge 3 ] && [ "$current_jobs" -gt 1 ]; then
        new_jobs=$(( current_jobs > 2 ? current_jobs - 2 : 1 ))
        warn "Observed ${transient_hits} rate-limit-style errors in last chunk — reducing parallelism ${current_jobs} → ${new_jobs} for remaining domains"
        current_jobs="$new_jobs"
        > "$TRANSIENT_COUNTER"
    fi

    idx=$(( idx + CHUNK_SIZE ))
done
rm -f "$TRANSIENT_COUNTER" "$TRANSIENT_LCK"

if check_abort; then
    err "Pipeline ABORTED: $(cat "$ABORT_FLAG" 2>/dev/null)"
    err "Some domains below were not checked — re-run after fixing the issue above."
    echo "" >&2
else
    log "All checks complete"
fi

# ══ FINAL REPORT ══════════════════════════════════════════════════
OK=$(grep -c      ',OK$'             "$REPORT" || true)
FAIL=$(grep -c    ',FAILED$'        "$REPORT" || true)
CLEAN=$(grep -c   ',CLEAN,'         "$REPORT" || true)
NOIDX=$(grep -c   ',NOT_INDEXED,'   "$REPORT" || true)
SPAM=$(grep -c    ',SPAM,'          "$REPORT" || true)
PENDING=$(grep -c ',PENDING$'       "$REPORT" || true)
SKIPPED=$(grep -c ',SKIPPED_CHEAP_FILTER$' "$REPORT" || true)
DBL_LISTED=$(grep -cE ',LISTED_[A-Z_]+,' "$REPORT" || true)
PARKED=$(grep -cE ',PARKED_HISTORY,' "$REPORT" || true)
GRADE_A=$(awk -F',' '$49=="A"' "$REPORT" | wc -l || true)
GRADE_B=$(awk -F',' '$49=="B"' "$REPORT" | wc -l || true)
SPIKES=$(grep -cE 'SPIKE'           "$REPORT" || true)
FOREIGN=$(grep -c 'HIGH_FOREIGN'    "$REPORT" || true)

echo -e "\n${W}══ FINAL REPORT ══${N}" >&2
if [ "${PENDING:-0}" -gt 0 ] 2>/dev/null; then
    echo -e "${R}${W}  ⚠ WARNING: ${PENDING} domains were never checked (pipeline aborted early) ⚠${N}" >&2
    echo -e "${R}  This report is INCOMPLETE. Fix the issue above and re-run.${N}" >&2
fi
# IMPORTANT: every counter below (Indexed clean, Grade A, etc.) is
# computed from the FULL report CSV, which includes domains served
# from cache. TOTAL/"Checked" only ever counted domains that went
# through a FRESH check this run — showing it alone next to those
# full-CSV counters made a working cache look like a counting bug
# (e.g. "Checked: 75" next to "Indexed clean: 85" looks impossible
# until you realize 25 more domains were served from cache and are
# included in the 85 but not the 75). Show the full breakdown so the
# two numbers never appear to silently contradict each other again.
n_in_report=$(( $(wc -l < "$REPORT" 2>/dev/null || echo 1) - 1 ))
printf "  %-24s %s\n"                             "Total in report:" "$n_in_report" >&2
printf "  %-24s %s\n"                             "  Freshly checked:" "$TOTAL"    >&2
printf "  %-24s %s\n"                             "  Served from cache:" "${n_cached:-0}" >&2
printf "  %-24s ${G}%s${N}  Taken: ${R}%s${N}\n" "Free:"            "$FREE_N"   "$TAKEN_N" >&2
printf "  %-24s ${R}%s${N}\n"                     "Never checked:"   "$PENDING"  >&2
printf "  %-24s ${Y}%s${N}\n"                     "Skipped (empty):" "$SKIPPED"  >&2
printf "  %-24s ${R}%s${N}\n"                     "Spamhaus listed:" "$DBL_LISTED" >&2
printf "  %-24s ${Y}%s${N}\n"                     "Parked history:"  "$PARKED"   >&2
printf "  %-24s ${G}%s${N}\n"                     "Grade A (75+):"   "$GRADE_A"  >&2
printf "  %-24s ${G}%s${N}\n"                     "Grade B (60+):"   "$GRADE_B"  >&2
printf "  %-24s ${G}%s${N}\n"                     "Indexed clean:"   "$CLEAN"    >&2
printf "  %-24s ${Y}%s${N}\n"                     "Not indexed:"     "$NOIDX"    >&2
printf "  %-24s ${R}%s${N}\n"                     "Spam content:"    "$SPAM"     >&2
printf "  %-24s ${R}%s${N}\n"                     "Link spikes:"     "$SPIKES"   >&2
printf "  %-24s ${R}%s${N}\n"                     "Foreign spam:"    "$FOREIGN"  >&2
printf "  %-24s ${G}%s${N}  Failed: ${R}%s${N}\n" "Backlinks OK:"   "$OK"       "$FAIL" >&2

echo -e "\n  ${W}Top free domains by SCORE:${N}" >&2
grep ',FREE,' "$REPORT" | grep -v ',TAKEN,' \
    | sort -t',' -k48 -rn | head -10 \
    | awk -F',' '{printf "  %-32s Score:%-5s Grade:%-3s DR:%-5s Index:%-14s\n",$1,$48,$49,$5,$3}' >&2

echo "" >&2
ok "Report: $REPORT"
ok "Log:    $LOG"
echo "" >&2
