#!/bin/bash
# lib.sh — Domain Hunter Toolkit library

R='\033[0;91m' G='\033[0;92m' Y='\033[0;93m' B='\033[0;94m' W='\033[1m' N='\033[0m'

log()  { echo -e "${B}[$(date '+%H:%M:%S')]${N} $1" | tee -a "$LOG" >&2; }
ok()   { echo -e "${G}[$(date '+%H:%M:%S')] ✓${N} $1" | tee -a "$LOG" >&2; }
warn() { echo -e "${Y}[$(date '+%H:%M:%S')] ⚠${N} $1" | tee -a "$LOG" >&2; }
err()  { echo -e "${R}[$(date '+%H:%M:%S')] ✗${N} $1" | tee -a "$LOG" >&2; }

is_transient() {
    case "$1" in
        40101|40103|40202|40209|50000|50301|50303|50401|50402) return 0 ;;
        *) return 1 ;;
    esac
}

is_fatal() {
    case "$1" in
        40100|40104|40200|40204|40207|40210) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Sanitize free text before it enters CSV or pipe-delimited fields ──
# Anchor text, domain names in spam reports, and similar fields come
# straight from external APIs and can contain commas, pipes, quotes,
# or newlines — any of which would corrupt our CSV rows or break
# sed/awk delimiters downstream. Strip them and cap length.
sanitize_field() {
    local text="$1"
    echo "$text" \
        | tr -d '\n\r' \
        | tr ',|"' '   ' \
        | cut -c1-80
}

dfs_call() {
    local endpoint="$1" payload="$2"
    local max="${MAX_RETRIES:-3}" base="${RETRY_DELAY:-2}" attempt=1

    [ -z "${DATAFORSEO_TOKEN:-}" ] && { err "DATAFORSEO_TOKEN not set"; exit 2; }

    while [ "$attempt" -le "$max" ]; do
        local r
        r=$(curl -s --max-time "${TIMEOUT:-15}" \
            -X POST "https://api.dataforseo.com/v3/${endpoint}" \
            -H "Authorization: Basic ${DATAFORSEO_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$payload" 2>/dev/null)
        local curl_exit=$?

        if [ "$curl_exit" -ne 0 ]; then
            warn "[${endpoint}] curl failed (exit ${curl_exit}), attempt ${attempt}/${max}"
            sleep $(( base * (2 ** (attempt - 1)) ))
            (( attempt++ )) || true
            continue
        fi

        local sc msg
        sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
        msg=$(echo "$r" | jq -r '.tasks[0].status_message // "unknown"' 2>/dev/null || echo "unknown")

        [ "$sc" = "20000" ] && { echo "$r"; return 0; }

        if is_fatal "$sc"; then
            err "[${endpoint}] Fatal error ${sc}: ${msg} — aborting"
            exit 2
        fi

        if is_transient "$sc"; then
            local delay=$(( base * (2 ** (attempt - 1)) ))
            warn "[${endpoint}] Transient error ${sc}: ${msg} — retrying in ${delay}s (${attempt}/${max})"
            sleep "$delay"
            (( attempt++ )) || true
            continue
        fi

        # Non-retryable non-fatal — return response so caller can inspect sc
        warn "[${endpoint}] Non-retryable error ${sc}: ${msg}"
        echo "$r"
        return 1
    done

    warn "[${endpoint}] All ${max} attempts failed"
    return 1
}

# ── CHECK 2: Google Index ─────────────────────────────────────────
api_index() {
    local domain="$1"
    local r sc

    r=$(dfs_call "serp/google/organic/live/advanced" \
        "[{\"keyword\":\"site:${domain}\",\"location_name\":\"United States\",\"language_name\":\"English\",\"depth\":10}]" \
        2>/dev/null) || true

    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)

    if [ "$sc" != "20000" ]; then
        [ "$sc" = "40102" ] && { echo "NOT_INDEXED|0"; return 0; }
        echo "ERR|0"; return 0
    fi

    local pages
    pages=$(echo "$r" | jq -r '(.tasks[0].result[0].items // []) | length' 2>/dev/null || echo 0)

    local content
    content=$(echo "$r" | jq -r \
        '.tasks[0].result[0].items[]? | select(.type=="organic") | "\(.title//"") \(.description//"")"' \
        2>/dev/null | tr '[:upper:]' '[:lower:]' || true)

    local status="NOT_INDEXED"
    if [ "${pages:-0}" -gt 0 ] 2>/dev/null; then
        echo "$content" | grep -qiE "casino|poker|viagra|pharmacy|porn|gambling|slots|crypto|hack|torrent" \
            && status="SPAM" || status="CLEAN"
    fi
    echo "${status}|${pages}"
}

# ── CHECK 3: Backlinks ────────────────────────────────────────────
api_backlinks() {
    local domain="$1"
    local r
    r=$(dfs_call "backlinks/summary/live" \
        "[{\"target\":\"${domain}\",\"include_subdomains\":true}]" 2>/dev/null) || true

    local sc
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    [ "$sc" != "20000" ] && { echo "ERR|ERR|ERR|ERR"; return 0; }

    echo "$r" | jq -r '.tasks[0].result[0] | "\(.rank//0)|\(.backlinks//0)|\(.referring_domains//0)|\(.backlinks_spam_score//0)"' \
        2>/dev/null || echo "ERR|ERR|ERR|ERR"
}

# ── CHECK 4: Wayback Machine ──────────────────────────────────────
api_wayback() {
    local domain="$1"
    local base="http://web.archive.org/cdx/search/cdx"

    local first_raw last_raw count_raw
    first_raw=$(curl -s --max-time 10 \
        "${base}?url=${domain}&output=json&limit=1&fl=timestamp&filter=statuscode:200&from=19900101" \
        2>/dev/null || true)
    last_raw=$(curl -s --max-time 10 \
        "${base}?url=${domain}&output=json&limit=1&fl=timestamp&filter=statuscode:200&reverse=true" \
        2>/dev/null || true)
    count_raw=$(curl -s --max-time 10 \
        "${base}?url=${domain}&output=json&limit=1&showNumPages=true" \
        2>/dev/null || true)

    local first_date last_date
    first_date=$(echo "$first_raw" | jq -r 'if length > 1 then .[1][0] else "" end' 2>/dev/null || true)
    last_date=$(echo "$last_raw"  | jq -r 'if length > 1 then .[1][0] else "" end' 2>/dev/null || true)

    local snap_count
    snap_count=$(echo "$count_raw" | grep -oE '^[0-9]+' | head -1 || true)
    snap_count="${snap_count:-0}"

    local first_year="N/A" last_year="N/A" age="N/A"
    [[ "$first_date" =~ ^[0-9]{4} ]] && { first_year="${first_date:0:4}"; age=$(( $(date +%Y) - first_year )); }
    [[ "$last_date"  =~ ^[0-9]{4} ]] && last_year="${last_date:0:4}"

    echo "${first_year}|${last_year}|${age}|${snap_count}"
}

# ── CHECK 5: Niche consistency ────────────────────────────────────
api_niche() {
    local domain="$1"
    local snapshots
    snapshots=$(curl -s --max-time 15 \
        "http://web.archive.org/cdx/search/cdx?url=${domain}&output=json&fl=timestamp&filter=statuscode:200&limit=5&from=20050101" \
        2>/dev/null || true)

    local snap_count
    snap_count=$(echo "$snapshots" | jq 'length' 2>/dev/null || echo 0)
    [ "${snap_count:-0}" -le 1 ] 2>/dev/null && { echo "UNKNOWN|0|UNKNOWN"; return 0; }

    local prev_niche="" changes=0 dominant="UNKNOWN"
    while IFS= read -r ts; do
        [ -z "$ts" ] && continue
        local content
        content=$(curl -s --max-time 8 -L "https://web.archive.org/web/${ts}/${domain}" 2>/dev/null \
            | sed 's/<[^>]*>//g' | tr '[:upper:]' '[:lower:]' | tr -s ' \n\t' ' ' | head -c 2000 || true)
        local niche="OTHER"
        echo "$content" | grep -qiE "casino|poker|gambling|bet|slot"   && niche="GAMBLING"
        echo "$content" | grep -qiE "viagra|pharmacy|pills|medication"  && niche="PHARMA"
        echo "$content" | grep -qiE "bitcoin|crypto|nft|blockchain"     && niche="CRYPTO"
        echo "$content" | grep -qiE "porn|xxx|adult|sex|nude"           && niche="ADULT"
        echo "$content" | grep -qiE "news|blog|article|journal"         && niche="MEDIA"
        echo "$content" | grep -qiE "shop|buy|store|product"            && niche="ECOMMERCE"
        echo "$content" | grep -qiE "tech|software|app|developer|code"  && niche="TECH"
        echo "$content" | grep -qiE "health|fitness|diet|wellness"      && niche="HEALTH"
        echo "$content" | grep -qiE "finance|loan|insurance|invest"     && niche="FINANCE"
        [ -n "$prev_niche" ] && [ "$prev_niche" != "$niche" ] && (( changes++ )) || true
        prev_niche="$niche"; dominant="$niche"
    done < <(echo "$snapshots" | jq -r 'if length > 1 then .[1:][] | .[0] else empty end' 2>/dev/null || true)

    local consistency="CONSISTENT"
    [ "${changes:-0}" -ge 2 ] 2>/dev/null && consistency="INCONSISTENT"
    [ "${changes:-0}" -ge 3 ] 2>/dev/null && consistency="UNSTABLE"
    echo "${consistency}|${changes}|${dominant}"
}

# ── CHECK 6: Redirect checker ─────────────────────────────────────
api_redirects() {
    local domain="$1"
    local result
    result=$(curl -s --max-time 10 -L -o /dev/null \
        -w "%{http_code}|%{url_effective}|%{num_redirects}" \
        "http://${domain}" 2>/dev/null || echo "ERR|ERR|0")

    local code final_url hops
    IFS='|' read -r code final_url hops <<< "$result"
    [[ "$hops" =~ ^[0-9]+$ ]] || hops=0

    local status="OK"
    if [ -n "$final_url" ] && [ "$final_url" != "ERR" ]; then
        local fd od
        fd=$(echo "$final_url" | sed 's|https\?://||;s|/.*||;s/^www\.//')
        od=$(echo "$domain" | sed 's/^www\.//')
        [ "$fd" != "$od" ] && status="REDIRECTS_AWAY"
    fi
    [ "$hops" -gt 2 ] 2>/dev/null && status="CHAIN_TOO_LONG"
    [ "$code" = "ERR" ]            && status="UNREACHABLE"
    echo "${status}|${hops}"
}

# ── CHECK 7: Anchor text ──────────────────────────────────────────
api_anchors() {
    local domain="$1"
    local r sc
    r=$(dfs_call "backlinks/anchors/live" \
        "[{\"target\":\"${domain}\",\"limit\":20,\"include_subdomains\":true}]" 2>/dev/null) || true
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    [ "$sc" != "20000" ] && { echo "ERR|0|N/A"; return 0; }

    local total top_anchor top_bl second_bl
    total=$(echo "$r"      | jq -r '.tasks[0].result[0].total_count // 0' 2>/dev/null || true)
    top_anchor=$(echo "$r" | jq -r '.tasks[0].result[0].items[0].anchor // "N/A"' 2>/dev/null || true)
    top_anchor=$(sanitize_field "$top_anchor")
    top_bl=$(echo "$r"     | jq -r '.tasks[0].result[0].items[0].backlinks // 0' 2>/dev/null || true)
    second_bl=$(echo "$r"  | jq -r '.tasks[0].result[0].items[1].backlinks // 0' 2>/dev/null || true)

    local flag="OK"
    if [ "${top_bl:-0}" -gt 0 ] && [ "${second_bl:-0}" -gt 0 ] 2>/dev/null; then
        local ratio=$(( top_bl * 100 / (top_bl + second_bl) ))
        [ "$ratio" -gt 70 ] 2>/dev/null && flag="OVER_OPTIMISED"
    fi
    [ "$top_anchor" = "$domain" ] && flag="SELF_REFERENTIAL"
    echo "${flag}|${total}|${top_anchor}"
}

# ── CHECK 8: Spam referring domains ──────────────────────────────
api_spam_domains() {
    local domain="$1"
    local r sc
    r=$(dfs_call "backlinks/referring_domains/live" \
        "[{\"target\":\"${domain}\",\"limit\":50,\"order_by\":[\"backlinks_spam_score,desc\"],\"include_subdomains\":true}]" \
        2>/dev/null) || true
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    [ "$sc" != "20000" ] && { echo "ERR|ERR|ERR|ERR"; return 0; }

    local total top_dom top_sc top3 all_bl
    total=$(echo "$r"   | jq -r '.tasks[0].result[0].total_count // 0' 2>/dev/null || true)
    top_dom=$(echo "$r" | jq -r '.tasks[0].result[0].items[0].domain // "N/A"' 2>/dev/null || true)
    top_dom=$(sanitize_field "$top_dom")
    top_sc=$(echo "$r"  | jq -r '.tasks[0].result[0].items[0].backlinks_spam_score // 0' 2>/dev/null || true)
    top3=$(echo "$r"    | jq -r '[.tasks[0].result[0].items[:3][].backlinks // 0] | add // 0' 2>/dev/null || true)
    all_bl=$(echo "$r"  | jq -r '[.tasks[0].result[0].items[].backlinks // 0] | add // 0' 2>/dev/null || true)

    local conc="DISTRIBUTED"
    if [ "${top3:-0}" -gt 0 ] && [ "${all_bl:-0}" -gt 0 ] 2>/dev/null; then
        local pct=$(( top3 * 100 / all_bl ))
        [ "$pct" -gt 60 ] 2>/dev/null && conc="CONCENTRATED"
    fi
    echo "${total}|${top_dom}|${top_sc}|${conc}"
}

# ── CHECK 9: Link ratio ───────────────────────────────────────────
api_tf_cf() {
    local domain="$1"
    local r sc
    r=$(dfs_call "backlinks/summary/live" \
        "[{\"target\":\"${domain}\",\"include_subdomains\":true}]" 2>/dev/null) || true
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    [ "$sc" != "20000" ] && { echo "ERR|ERR|ERR|ERR"; return 0; }

    local rd bl ratio="N/A" flag="OK"
    rd=$(echo "$r" | jq -r '.tasks[0].result[0].referring_domains // 0' 2>/dev/null || true)
    bl=$(echo "$r" | jq -r '.tasks[0].result[0].backlinks // 0' 2>/dev/null || true)

    if [ "${rd:-0}" -gt 0 ] && [ "${bl:-0}" -gt 0 ] 2>/dev/null; then
        ratio=$(( bl / rd ))
        [ "$ratio" -gt 20 ] 2>/dev/null && flag="HIGH_CONCENTRATION"
        [ "$ratio" -gt 50 ] 2>/dev/null && flag="LIKELY_SCHEME"
    fi
    echo "${rd}|${bl}|${ratio}|${flag}"
}

# ── CHECK 10: Google cache ────────────────────────────────────────
api_cache() {
    local domain="$1"
    local code
    code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
        -A "Mozilla/5.0 (compatible; Googlebot/2.1)" \
        "https://webcache.googleusercontent.com/search?q=cache:${domain}" \
        2>/dev/null || echo "ERR")
    case "$code" in
        200) echo "CACHED" ;;
        404) echo "NOT_CACHED" ;;
        429) echo "RATE_LIMITED" ;;
        ERR) echo "UNREACHABLE" ;;
        *)   echo "UNKNOWN" ;;
    esac
}

# ── Report helpers ────────────────────────────────────────────────
csv_write()  { ( flock -x 9; echo "$1" >> "$REPORT" ) 9>"$RPT_LCK"; }
csv_update() {
    # $1 = domain to match (first CSV field), $2 = full replacement line
    # Uses awk instead of sed -i because anchor text / domain content
    # can contain pipes, slashes, or other characters that break sed's
    # delimiter — awk matches on the literal first field instead.
    #
    # Each call uses its own uniquely-named temp file (PID + random)
    # rather than a shared "$REPORT.tmp" path. With 5+ parallel workers
    # all calling csv_update, a shared temp filename is a race risk:
    # even inside flock, filesystem mv/rename timing on a shared path
    # can let one worker's write clobber another's in-flight read.
    # A unique temp file per call removes that risk entirely.
    local domain="$1" newline="$2"
    local tmpfile="${REPORT}.tmp.$$.${RANDOM}"
    ( flock -x 9
      awk -F',' -v dom="$domain" -v newline="$newline" '
          BEGIN { found=0 }
          $1 == dom && !found { print newline; found=1; next }
          { print }
      ' "$REPORT" > "$tmpfile" && mv "$tmpfile" "$REPORT"
    ) 9>"$RPT_LCK"
    rm -f "$tmpfile" 2>/dev/null || true
}

# ── CHECK 11: Foreign language anchor spam ────────────────────────
# Detects Chinese/Japanese/Russian/Arabic script in anchor text using
# UTF-8 byte-ratio analysis rather than jq's Unicode regex — jq/Oniguruma
# \uXXXX escapes inside a bash double-quoted string get double-escaped
# and silently fail to match anything meaningful, which was flagging
# 100% of anchors (including plain English) as "foreign" in earlier
# versions. Counting non-printable/non-ASCII bytes relative to string
# length reliably separates genuine CJK/Cyrillic/Arabic script (>70%
# non-ASCII) from plain English or Latin-with-accents text (near 0%).
api_foreign_anchors() {
    local domain="$1"
    local r sc
    r=$(dfs_call "backlinks/anchors/live" \
        "[{\"target\":\"${domain}\",\"limit\":100,\"include_subdomains\":true}]" 2>/dev/null) || true
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    [ "$sc" != "20000" ] && { echo "0|0|OK"; return 0; }

    local fetched
    fetched=$(echo "$r" | jq -r '.tasks[0].result[0].items | length' 2>/dev/null || echo 0)
    [ "${fetched:-0}" -eq 0 ] && { echo "0|0|OK"; return 0; }

    # Pull all anchor texts, one per line
    local anchors
    anchors=$(echo "$r" | jq -r '.tasks[0].result[0].items[]?.anchor // ""' 2>/dev/null || true)

    local foreign=0 gambling_hit=0
    while IFS= read -r anchor; do
        [ -z "$anchor" ] && continue
        local len non_ascii ratio
        len=${#anchor}
        [ "$len" -eq 0 ] && continue
        non_ascii=$(printf '%s' "$anchor" | LC_ALL=C grep -o '[^[:print:][:space:]]' | wc -l)
        ratio=$(( non_ascii * 100 / len ))
        [ "$ratio" -gt 70 ] && (( foreign++ )) || true

        # Known gambling/casino terms transliterated into CJK/Cyrillic —
        # checked with plain grep, no Unicode regex escaping involved
        if echo "$anchor" | grep -qE "华体会|博彩|赌场|彩票|казино|ставки"; then
            (( gambling_hit++ )) || true
        fi
    done <<< "$anchors"

    local pct=$(( foreign * 100 / fetched ))
    local flag="OK"
    if [ "$gambling_hit" -gt 0 ]; then
        flag="FOREIGN_GAMBLING_SPAM"
    elif [ "$pct" -gt 30 ]; then
        flag="HIGH_FOREIGN"
    elif [ "$pct" -gt 10 ]; then
        flag="SOME_FOREIGN"
    fi

    echo "${foreign}|${pct}|${flag}"
}

# ── CHECK 12: Link velocity — when were links built? ─────────────
# Detects unnatural spikes in link building
api_link_velocity() {
    local domain="$1"
    local r sc
    r=$(dfs_call "backlinks/timeseries_summary/live" \
        "[{\"target\":\"${domain}\",\"date_from\":\"$(date -d '2 years ago' +%Y-%m-%d 2>/dev/null || date -v-2y +%Y-%m-%d 2>/dev/null || echo '2023-01-01')\",\"date_to\":\"$(date +%Y-%m-%d)\",\"group_by\":\"month\",\"include_subdomains\":true}]" \
        2>/dev/null) || true
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    [ "$sc" != "20000" ] && { echo "OK|0|0"; return 0; }

    # Get monthly new backlink counts
    local counts
    counts=$(echo "$r" | jq -r '.tasks[0].result[0].items[]?.new_backlinks // 0' 2>/dev/null || true)

    if [ -z "$counts" ]; then
        echo "OK|0|0"; return 0
    fi

    # Find max month and total
    local max_month=0 total_bl=0
    while IFS= read -r n; do
        [[ "$n" =~ ^[0-9]+$ ]] || continue
        total_bl=$(( total_bl + n )) || true
        [ "$n" -gt "$max_month" ] && max_month="$n"
    done <<< "$counts"

    # If one month accounts for >60% of all links = spike
    local flag="OK" spike_pct=0
    if [ "${total_bl:-0}" -gt 0 ] && [ "${max_month:-0}" -gt 0 ] 2>/dev/null; then
        spike_pct=$(( max_month * 100 / total_bl )) 2>/dev/null || true
        [ "$spike_pct" -gt 60 ] && flag="SPIKE"
        [ "$spike_pct" -gt 80 ] && flag="SEVERE_SPIKE"
    fi

    echo "${flag}|${max_month}|${spike_pct}"
}

# ── CHECK 13: Referring IP diversity ─────────────────────────────
# Are links coming from diverse IP ranges or same hosting provider?
api_ip_diversity() {
    local domain="$1"
    local r sc
    r=$(dfs_call "backlinks/referring_networks/live" \
        "[{\"target\":\"${domain}\",\"limit\":50,\"include_subdomains\":true}]" \
        2>/dev/null) || true
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    [ "$sc" != "20000" ] && { echo "ERR|0|0"; return 0; }

    local total_networks unique_ips flag="OK"
    total_networks=$(echo "$r" | jq -r '.tasks[0].result[0].total_count // 0' 2>/dev/null || echo 0)

    # Check top network concentration
    local top_net_bl all_bl
    top_net_bl=$(echo "$r" | jq -r '.tasks[0].result[0].items[0].backlinks // 0' 2>/dev/null || echo 0)
    all_bl=$(echo "$r" | jq -r '[.tasks[0].result[0].items[].backlinks // 0] | add // 0' 2>/dev/null || echo 0)

    local conc_pct=0
    if [ "${all_bl:-0}" -gt 0 ] && [ "${top_net_bl:-0}" -gt 0 ] 2>/dev/null; then
        conc_pct=$(( top_net_bl * 100 / all_bl )) 2>/dev/null || true
        [ "$conc_pct" -gt 60 ] && flag="LOW_DIVERSITY"
        [ "$conc_pct" -gt 80 ] && flag="SINGLE_HOST"
    fi

    echo "${flag}|${total_networks}|${conc_pct}"
}

# ── Composite score calculator ────────────────────────────────────
# Called after all checks — returns score|grade|flags
calculate_score() {
    local idx_status="$1" dr="$2" bl="$3" spam_score="$4"
    local niche_status="$5" redir_status="$6" anc_flag="$7"
    local link_flag="$8" cache_status="$9" wb_age="${10}"
    local spd_count="${11}" velocity_flag="${12:-OK}"
    local foreign_flag="${13:-OK}" ip_flag="${14:-OK}"

    local score=50 flags=""

    case "$idx_status" in
        CLEAN)        (( score += 15 )) || true; flags+="CLEAN_INDEX," ;;
        NOT_INDEXED)  (( score -= 20 )) || true; flags+="NOT_INDEXED," ;;
        SPAM)         (( score -= 40 )) || true; flags+="SPAM_CONTENT," ;;
    esac

    if [[ "$dr" =~ ^[0-9]+$ ]]; then
        if   [ "$dr" -ge 70 ]; then (( score += 20 )) || true; flags+="HIGH_DR,"
        elif [ "$dr" -ge 40 ]; then (( score += 12 )) || true; flags+="MED_DR,"
        elif [ "$dr" -ge 20 ]; then (( score += 6  )) || true
        fi
    fi

    if [[ "$bl" =~ ^[0-9]+$ ]]; then
        if   [ "$bl" -ge 10000 ]; then (( score += 10 )) || true
        elif [ "$bl" -ge 1000  ]; then (( score += 6  )) || true
        elif [ "$bl" -ge 100   ]; then (( score += 3  )) || true
        fi
    fi

    if [[ "$spam_score" =~ ^[0-9]+$ ]]; then
        if   [ "$spam_score" -gt 50 ]; then (( score -= 20 )) || true; flags+="HIGH_SPAM,"
        elif [ "$spam_score" -gt 30 ]; then (( score -= 10 )) || true; flags+="MED_SPAM,"
        elif [ "$spam_score" -gt 15 ]; then (( score -= 5  )) || true
        fi
    fi

    case "$niche_status" in
        CONSISTENT)   (( score += 5  )) || true ;;
        INCONSISTENT) (( score -= 10 )) || true; flags+="NICHE_INCONSISTENT," ;;
        UNSTABLE)     (( score -= 20 )) || true; flags+="NICHE_UNSTABLE," ;;
    esac

    case "$redir_status" in
        REDIRECTS_AWAY) (( score -= 25 )) || true; flags+="REDIRECTS_AWAY," ;;
        CHAIN_TOO_LONG) (( score -= 10 )) || true; flags+="REDIRECT_CHAIN," ;;
    esac

    case "$anc_flag" in
        OVER_OPTIMISED)   (( score -= 10 )) || true; flags+="OVER_OPTIMISED," ;;
        SELF_REFERENTIAL) (( score -= 15 )) || true; flags+="SELF_REFERENTIAL," ;;
    esac

    case "$link_flag" in
        LIKELY_SCHEME)      (( score -= 20 )) || true; flags+="LINK_SCHEME," ;;
        HIGH_CONCENTRATION) (( score -= 8  )) || true; flags+="HIGH_LINK_CONC," ;;
    esac

    [ "$cache_status" = "CACHED"     ] && (( score += 8 )) || true
    [ "$cache_status" = "NOT_CACHED" ] && (( score -= 5 )) || true

    if [[ "$wb_age" =~ ^[0-9]+$ ]]; then
        if   [ "$wb_age" -ge 10 ]; then (( score += 10 )) || true; flags+="OLD_DOMAIN,"
        elif [ "$wb_age" -ge 5  ]; then (( score += 6  )) || true
        elif [ "$wb_age" -ge 2  ]; then (( score += 3  )) || true
        fi
    fi

    if [[ "$spd_count" =~ ^[0-9]+$ ]]; then
        if   [ "$spd_count" -gt 50 ]; then (( score -= 15 )) || true; flags+="MANY_SPAM_RD,"
        elif [ "$spd_count" -gt 20 ]; then (( score -= 8  )) || true
        elif [ "$spd_count" -gt 10 ]; then (( score -= 4  )) || true
        fi
    fi

    case "$velocity_flag" in
        SEVERE_SPIKE) (( score -= 20 )) || true; flags+="SEVERE_LINK_SPIKE," ;;
        SPIKE)        (( score -= 12 )) || true; flags+="LINK_SPIKE," ;;
    esac

    case "$foreign_flag" in
        FOREIGN_GAMBLING_SPAM) (( score -= 30 )) || true; flags+="FOREIGN_GAMBLING_SPAM," ;;
        HIGH_FOREIGN)          (( score -= 5  )) || true; flags+="HIGH_FOREIGN_CONTENT," ;;
        SOME_FOREIGN)          : ;;  # harmless — no penalty
    esac

    case "$ip_flag" in
        SINGLE_HOST)  (( score -= 15 )) || true; flags+="SINGLE_HOST_LINKS," ;;
        LOW_DIVERSITY)(( score -= 8  )) || true; flags+="LOW_IP_DIVERSITY," ;;
    esac

    [ "$score" -lt 0   ] && score=0
    [ "$score" -gt 100 ] && score=100

    local grade
    if   [ "$score" -ge 75 ]; then grade="A"
    elif [ "$score" -ge 60 ]; then grade="B"
    elif [ "$score" -ge 45 ]; then grade="C"
    elif [ "$score" -ge 30 ]; then grade="D"
    else                            grade="F"
    fi

    echo "${score}|${grade}|${flags%,}"
}
