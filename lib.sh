#!/bin/bash
# lib.sh — Domain Hunter Toolkit library v7 — performance pass
# Key changes from v6:
#  1. Merged api_backlinks + api_tf_cf into one call (was 2 identical API hits)
#  2. Merged api_anchors + api_foreign_anchors into one call (was 2 identical API hits)
#  3. Wayback/niche calls run with their own internal parallelism
#  4. All DataForSEO checks for one domain can now run via batch endpoint (see api_batch_check)
#  5. Cache check and redirect check combined into one curl invocation

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

# ── Cross-process abort signaling ─────────────────────────────────
# A fatal error (bad credentials, no balance, no subscription) means
# every subsequent API call will fail identically. But `exit 2` inside
# a worker only kills that ONE xargs-spawned subprocess — xargs simply
# launches the next domain in a fresh worker, which hits the same fatal
# error, dies, and so on. Without coordination, this produces a long
# string of silent per-worker deaths instead of a clean, immediate stop,
# and depending on timing can leave a handful of rows in an inconsistent
# state. ABORT_FLAG is a sentinel file: any worker can create it, and
# every worker checks for it before doing real work.
signal_abort() {
    local reason="$1"
    echo "${reason}" > "${ABORT_FLAG:-/tmp/dhp_abort_flag}" 2>/dev/null || true
}

check_abort() {
    [ -f "${ABORT_FLAG:-/tmp/dhp_abort_flag}" ] && return 0
    return 1
}

sanitize_field() {
    local text="$1"
    echo "$text" | tr -d '\n\r' | tr ',|"' '   ' | cut -c1-80
}

dfs_call() {
    local endpoint="$1" payload="$2" call_timeout="${3:-${TIMEOUT:-15}}"
    local max="${MAX_RETRIES:-3}" base="${RETRY_DELAY:-2}" attempt=1
    if [ -z "${DATAFORSEO_TOKEN:-}" ]; then
        err "DATAFORSEO_TOKEN not set"
        signal_abort "DATAFORSEO_TOKEN not set"
        exit 2
    fi

    while [ "$attempt" -le "$max" ]; do
        local r
        r=$(curl -s --max-time "${call_timeout}" \
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
            err "[${endpoint}] Fatal error ${sc}: ${msg} — aborting entire pipeline"
            signal_abort "${sc}: ${msg}"
            exit 2
        fi

        if is_transient "$sc"; then
            local delay=$(( base * (2 ** (attempt - 1)) ))
            warn "[${endpoint}] Transient error ${sc}: ${msg} — retrying in ${delay}s (${attempt}/${max})"
            # Bump the shared transient-error counter, if one is configured.
            # pipeline.sh reads this between chunks to decide whether to
            # scale parallelism down — a burst of transient errors usually
            # means we're pushing the API harder than it wants right now.
            if [ -n "${TRANSIENT_COUNTER:-}" ]; then
                ( flock -x 9; echo "x" >> "$TRANSIENT_COUNTER" ) 9>"${TRANSIENT_LCK:-/tmp/dhp_transient_lock}" 2>/dev/null || true
            fi
            sleep "$delay"
            (( attempt++ )) || true
            continue
        fi

        warn "[${endpoint}] Non-retryable error ${sc}: ${msg}"
        echo "$r"
        return 1
    done
    warn "[${endpoint}] All ${max} attempts failed"
    return 1
}

# ══════════════════════════════════════════════════════════════════
# OPTIMIZATION 1 — Merged backlinks + link-ratio check
# Was: api_backlinks() and api_tf_cf() each called backlinks/summary/live
# Now: api_backlinks_full() calls it ONCE and returns everything both
# checks need. Saves 1 full API round trip per domain.
# ══════════════════════════════════════════════════════════════════
api_backlinks_full() {
    local domain="$1"
    local r sc
    r=$(dfs_call "backlinks/summary/live" \
        "[{\"target\":\"${domain}\",\"include_subdomains\":true}]" 2>/dev/null) || true
    # dfs_call's `exit 2` on a fatal error only kills the command-
    # substitution subshell above — it can never propagate to this
    # function, and `|| true` would swallow the non-zero return even
    # if it could. Check the abort flag explicitly instead of relying
    # on exit code propagation that doesn't actually happen.
    check_abort && { echo "ERR|ERR|ERR|ERR|ERR|ERR|ERR"; return 1; }
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    [ "$sc" != "20000" ] && { echo "ERR|ERR|ERR|ERR|ERR|ERR|ERR"; return 0; }

    local dr bl rd spam
    IFS='|' read -r dr bl rd spam <<< "$(echo "$r" | jq -r \
        '.tasks[0].result[0] | "\(.rank//0)|\(.backlinks//0)|\(.referring_domains//0)|\(.backlinks_spam_score//0)"' \
        2>/dev/null || echo "ERR|ERR|ERR|ERR")"

    # link ratio fields come from the same payload — no second call needed
    local ratio="N/A" flag="OK"
    if [[ "$rd" =~ ^[0-9]+$ ]] && [[ "$bl" =~ ^[0-9]+$ ]] && [ "$rd" -gt 0 ] 2>/dev/null; then
        ratio=$(( bl / rd ))
        [ "$ratio" -gt 20 ] 2>/dev/null && flag="HIGH_CONCENTRATION"
        [ "$ratio" -gt 50 ] 2>/dev/null && flag="LIKELY_SCHEME"
    fi

    echo "${dr}|${bl}|${rd}|${spam}|${rd}|${bl}|${ratio}|${flag}"
}

# ── CHECK 2: Google Index ─────────────────────────────────────────
api_index() {
    local domain="$1"
    local r sc
    # SERP live-search endpoint runs an actual Google query server-side
    # and is measurably slower than DataForSEO's database-backed
    # endpoints (backlinks, anchors, etc). Production logs showed
    # repeated curl exit-28 timeouts at the default 15s under 5-way
    # parallel load — give this specific call more headroom (30s).
    r=$(dfs_call "serp/google/organic/live/advanced" \
        "[{\"keyword\":\"site:${domain}\",\"location_name\":\"United States\",\"language_name\":\"English\",\"depth\":10}]" \
        30 2>/dev/null) || true
    check_abort && { echo "ERR|0"; return 1; }
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    if [ "$sc" != "20000" ]; then
        [ "$sc" = "40102" ] && { echo "NOT_INDEXED|0"; return 0; }
        # Empty/unparseable response after all retries means the
        # endpoint timed out rather than returned an error — distinguish
        # this from a real API error so the CSV is debuggable without
        # digging through log files.
        [ -z "$r" ] && { echo "TIMEOUT|0"; return 0; }
        echo "ERR|0"; return 0
    fi
    local pages content status="NOT_INDEXED"
    pages=$(echo "$r" | jq -r '(.tasks[0].result[0].items // []) | length' 2>/dev/null || echo 0)
    content=$(echo "$r" | jq -r \
        '.tasks[0].result[0].items[]? | select(.type=="organic") | "\(.title//"") \(.description//"")"' \
        2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
    if [ "${pages:-0}" -gt 0 ] 2>/dev/null; then
        echo "$content" | grep -qiE "casino|poker|viagra|pharmacy|porn|gambling|slots|crypto|hack|torrent" \
            && status="SPAM" || status="CLEAN"
    fi
    echo "${status}|${pages}"
}

# ══════════════════════════════════════════════════════════════════
# OPTIMIZATION 2 — Merged Wayback checks (age + niche from same data)
# Was: api_wayback() made 3 curl calls, api_niche() made 1 CDX call
#      + up to 5 SEQUENTIAL page fetches (the single biggest latency
#      source in the whole pipeline — up to 15s alone)
# Now: one CDX call gets first/last/count, and the up-to-5 snapshot
# page fetches run in PARALLEL using background jobs + wait, not
# sequentially. This alone can cut 10-12 seconds off every domain.
# ══════════════════════════════════════════════════════════════════
api_wayback_and_niche() {
    local domain="$1"
    local base="http://web.archive.org/cdx/search/cdx"

    # Single combined CDX call: get first, last, AND up to 5 sample
    # timestamps spread across history all from ONE request instead
    # of three separate ones.
    local all_snaps
    all_snaps=$(curl -s --max-time 10 \
        "${base}?url=${domain}&output=json&fl=timestamp&filter=statuscode:200&collapse=timestamp:6" \
        2>/dev/null || true)

    local snap_count
    snap_count=$(echo "$all_snaps" | jq 'if length > 1 then length - 1 else 0 end' 2>/dev/null || echo 0)

    if [ "${snap_count:-0}" -eq 0 ]; then
        echo "N/A|N/A|N/A|0|UNKNOWN|0|UNKNOWN|OK"
        return 0
    fi

    local first_date last_date
    first_date=$(echo "$all_snaps" | jq -r '.[1][0] // ""' 2>/dev/null || true)
    last_date=$(echo "$all_snaps"  | jq -r '.[-1][0] // ""' 2>/dev/null || true)

    local first_year="N/A" last_year="N/A" age="N/A"
    [[ "$first_date" =~ ^[0-9]{4} ]] && { first_year="${first_date:0:4}"; age=$(( $(date +%Y) - first_year )); }
    [[ "$last_date"  =~ ^[0-9]{4} ]] && last_year="${last_date:0:4}"

    # Pick up to 8 evenly-spaced timestamps from the snapshots we
    # already have — no second CDX call needed. Raised from 5 to 8
    # since the fetches below already run in parallel rather than
    # sequentially, so more samples cost almost nothing extra in
    # wall-clock time but give meaningfully better coverage for the
    # content-quality (PARKED_HISTORY) check — 5 samples across a
    # domain's full multi-year history is a thin basis for "this was
    # always parked" vs "this had one bad stretch."
    local sample_ts
    sample_ts=$(echo "$all_snaps" | jq -r '
        .[1:] as $items |
        ($items | length) as $n |
        if $n <= 8 then $items[] | .[0]
        else [0, ($n/8|floor), (2*$n/8|floor), (3*$n/8|floor), (4*$n/8|floor), (5*$n/8|floor), (6*$n/8|floor), ($n-1)] | unique[] as $i | $items[$i][0]
        end
    ' 2>/dev/null || true)

    # Fetch all sample pages IN PARALLEL instead of sequentially.
    # This is the single biggest speed win in the whole check —
    # 5 sequential 2-3s fetches (~10-15s) becomes 1 parallel batch (~3s).
    local tmpdir="/tmp/dhp_niche_$$_${RANDOM}"
    mkdir -p "$tmpdir"
    local i=0
    while IFS= read -r ts; do
        [ -z "$ts" ] && continue
        (( i++ )) || true
        ( curl -s --max-time 8 -L "https://web.archive.org/web/${ts}/${domain}" 2>/dev/null \
            | sed 's/<[^>]*>//g' | tr '[:upper:]' '[:lower:]' | tr -s ' \n\t' ' ' | head -c 2000 \
            > "${tmpdir}/${i}.txt" ) &
    done <<< "$sample_ts"
    wait   # all fetches happen concurrently, we wait once for all of them

    local prev_niche="" changes=0 dominant="UNKNOWN"
    local parked_count=0 thin_count=0 total_snaps_checked=0
    for f in "${tmpdir}"/*.txt; do
        [ -f "$f" ] || continue
        local content niche="OTHER"
        content=$(cat "$f")
        (( total_snaps_checked++ )) || true

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

        # Content-quality pass on the SAME already-fetched text — was
        # this snapshot a real site, or a parked/for-sale placeholder?
        # Common parking-page boilerplate phrases used by GoDaddy,
        # Sedo, domain auction sites, and generic registrar parking
        # templates. A domain that's been a parking page across most
        # of its visible history was likely never a real site at all,
        # which is a meaningfully different (and worse) signal than
        # "real site that later shut down."
        if echo "$content" | grep -qiE \
            "this domain (may be|is) for sale|buy this domain|domain (parking|is parked)|inquire about this domain|related searches|this web ?page (is parked|parked free)|courtesy of|godaddy\.com|sedo\.com"; then
            (( parked_count++ )) || true
        fi

        # Thin-content check: after stripping HTML tags (already done
        # before this content was saved), a genuinely empty/near-empty
        # page leaves very little visible text. 50 chars is a rough
        # floor — real pages, even minimal ones, usually have a title
        # and at least a sentence of body text.
        local content_len=${#content}
        [ "$content_len" -lt 50 ] && (( thin_count++ )) || true
    done
    rm -rf "$tmpdir"

    local consistency="CONSISTENT"
    [ "${changes:-0}" -ge 2 ] 2>/dev/null && consistency="INCONSISTENT"
    [ "${changes:-0}" -ge 3 ] 2>/dev/null && consistency="UNSTABLE"

    # Content quality verdict — majority of CHECKED snapshots (not all
    # history, just the samples we fetched) showing parking/thin
    # content is a real signal: PARKED_HISTORY means this domain looks
    # like it's mostly been an empty placeholder rather than a real
    # site with content, which is a different (and generally worse,
    # for PBN purposes — no genuine link-earning history) profile than
    # a domain that had real content and later went dormant.
    local content_quality="OK"
    if [ "${total_snaps_checked:-0}" -gt 0 ]; then
        local bad_count=$(( parked_count > thin_count ? parked_count : thin_count ))
        if [ "$bad_count" -ge "$total_snaps_checked" ]; then
            content_quality="PARKED_HISTORY"
        elif [ "$bad_count" -gt 0 ]; then
            content_quality="PARTIAL_PARKED"
        fi
    fi

    echo "${first_year}|${last_year}|${age}|${snap_count}|${consistency}|${changes}|${dominant}|${content_quality}"
}

# ══════════════════════════════════════════════════════════════════
# CHECK 6 — Redirect checker
#
# NOTE: A "Google cache" check (api_cache) previously lived alongside
# this one. It has been REMOVED — Google permanently shut down public
# cache access on Sept 24, 2024 (officially confirmed by Google's
# Search Liaison Danny Sullivan). Every cache request now 302-redirects
# to a bot-detection page, returning the same useless "UNKNOWN" result
# for every domain, every time. This isn't fixable on our end; the
# underlying Google feature no longer exists. Google's own suggested
# replacement is the Wayback Machine, which we already check via
# api_wayback_and_niche(). No functional loss — just less wasted time.
# ══════════════════════════════════════════════════════════════════
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
    [ "$code" = "ERR" ] && status="UNREACHABLE"

    echo "${status}|${hops}"
}

# ══════════════════════════════════════════════════════════════════
# CHECK — robots.txt + sitemap.xml (free, no DataForSEO dependency)
#
# A direct independent site: search isn't realistically scriptable
# here — Google has no sanctioned free search API, and scraping
# google.com/search directly means fighting CAPTCHA walls, residential
# proxies, and TLS fingerprinting just to dodge bot detection. That's
# not a free check, it's an adversarial scraping project, and not
# something to build against a service that actively tries to block it.
#
# robots.txt and sitemap.xml ARE genuinely free and sanctioned —
# they're public files any domain's previous owner chose to publish
# (or not), fetched with a plain curl request, no API key, no paid
# endpoint. What they tell us:
#   - robots.txt missing entirely: no signal either way (common, normal)
#   - robots.txt with "Disallow: /": previous owner deliberately
#     blocked ALL crawlers — a real, deliberate signal worth flagging,
#     not a neutral default
#   - sitemap.xml present + URL count: rough proxy for site size/effort,
#     useful alongside the Wayback snapshot count we already track
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
# CHECK — Spamhaus Domain Blocklist (DBL), free, no API key
#
# The DBL is a public DNSBL queried via a plain DNS lookup against
# <domain>.dbl.spamhaus.org — no HTTP request, no API key, no rate
# limit beyond Spamhaus' fair-use policy (free for low-volume,
# non-commercial use, which this pipeline's scale comfortably fits).
# This is exactly the documented, sanctioned usage pattern — querying
# real candidate domains via the DNS protocol is how DBL is meant to
# be used, distinct from scraping their web-based reputation checker.
#
# Why this matters for PBN vetting specifically: if you've recently
# bought a domain, it may already be on a Spamhaus blocklist if it
# was used for spam by its previous owner — exactly the scenario this
# whole pipeline exists to catch, and DBL listings often predate or
# corroborate what our own spam-score/backlink checks find.
#
# Return code meaning (from Spamhaus docs):
#   127.0.1.2   spam domain
#   127.0.1.4   phish domain
#   127.0.1.5   malware domain
#   127.0.1.6   botnet C&C domain
#   127.0.1.10x abused-legit (compromised, not the owner's doing)
#   NXDOMAIN    not listed (the normal, expected case)
#
# Requires `dig` or `host` (the `dnsutils`/`bind9-dnsutils` package).
# Falls back to NOT_CHECKED gracefully if neither is installed, same
# pattern as the sqlite3 cache graceful-degradation.
# ══════════════════════════════════════════════════════════════════
api_spamhaus_dbl() {
    local domain="$1"
    local query="${domain}.dbl.spamhaus.org"
    local result=""

    if command -v dig &>/dev/null; then
        result=$(dig +short +time=5 +tries=1 "$query" A 2>/dev/null || true)
    elif command -v host &>/dev/null; then
        result=$(host -W 5 "$query" 2>/dev/null | grep -oE '127\.0\.1\.[0-9]+' || true)
    else
        echo "NOT_CHECKED|N/A"
        return 0
    fi

    if [ -z "$result" ]; then
        echo "CLEAN|N/A"
        return 0
    fi

    local code status
    code=$(echo "$result" | head -1 | grep -oE '127\.0\.1\.[0-9]+' || true)
    case "$code" in
        127.0.1.2)   status="LISTED_SPAM" ;;
        127.0.1.4)   status="LISTED_PHISH" ;;
        127.0.1.5)   status="LISTED_MALWARE" ;;
        127.0.1.6)   status="LISTED_BOTNET" ;;
        127.0.1.10*) status="LISTED_ABUSED_LEGIT" ;;
        "")          echo "CLEAN|N/A"; return 0 ;;
        *)           status="LISTED_OTHER" ;;
    esac
    echo "${status}|${code}"
}

# ══════════════════════════════════════════════════════════════════
# CHECK — Current hosting footprint (nameserver provider), free
#
# Historical DNS data (has this domain bounced through sketchy hosts
# over time) requires a paid third-party feed — same dead end we hit
# with Ahrefs/Majestic. But CURRENT nameservers are free: a plain dig
# NS query, no API key. This flags a small set of nameserver patterns
# commonly associated with disposable/free DNS setups often used for
# quick, low-effort PBN nodes — not proof of anything by itself, but
# a cheap additional data point alongside the IP diversity check we
# already have.
#
# This is deliberately a SMALL, conservative pattern list, not an
# attempt to comprehensively judge every registrar/host — false
# positives here just mean an unremarkable hosting setup gets a
# neutral flag, not a penalty; nothing in this check feeds the score
# yet, it's informational only until validated against real outcomes.
# ══════════════════════════════════════════════════════════════════
api_hosting_footprint() {
    local domain="$1"
    local ns_records=""

    if command -v dig &>/dev/null; then
        ns_records=$(dig +short +time=5 +tries=1 NS "$domain" 2>/dev/null || true)
    elif command -v host &>/dev/null; then
        ns_records=$(host -t NS "$domain" 2>/dev/null | grep -oE '[a-zA-Z0-9.-]+\.$' || true)
    else
        echo "NOT_CHECKED|N/A"
        return 0
    fi

    if [ -z "$ns_records" ]; then
        echo "NO_NS|N/A"
        return 0
    fi

    local first_ns
    first_ns=$(echo "$ns_records" | head -1 | tr '[:upper:]' '[:lower:]')

    local flag="OK"
    # Small, conservative list — flag known free/throwaway-tier DNS
    # providers commonly seen on quickly-assembled low-effort sites.
    # Being hosted on one of these is NOT inherently bad (plenty of
    # legitimate sites use Cloudflare, for instance) — this is informational,
    # not a penalty, until validated against real outcomes.
    case "$first_ns" in
        *freenom*|*afraid.org*|*hostingsupport*) flag="DISPOSABLE_DNS" ;;
        *cloudflare*) flag="CLOUDFLARE" ;;
        *domaincontrol*) flag="GODADDY" ;;
        *registrar-servers*) flag="NAMECHEAP" ;;
        *) flag="OTHER" ;;
    esac

    echo "${flag}|${first_ns}"
}

api_robots_sitemap() {
    local domain="$1"
    local robots_body robots_code sitemap_url sitemap_code sitemap_body
    local robots_status="MISSING" sitemap_status="MISSING" url_count=0

    robots_body=$(curl -s --max-time 8 -L -w "\n%{http_code}" \
        "http://${domain}/robots.txt" 2>/dev/null || echo "ERR")
    robots_code=$(echo "$robots_body" | tail -1)
    robots_body=$(echo "$robots_body" | sed '$d')

    if [ "$robots_code" = "200" ] && [ -n "$robots_body" ]; then
        robots_status="OK"
        # Blanket disallow check: a bare "Disallow: /" with no path
        # after it (ignoring whitespace) blocks everything. Case-
        # insensitive since robots.txt directives aren't formally
        # case-sensitive in practice across different server setups.
        if echo "$robots_body" | grep -qiE '^[[:space:]]*disallow:[[:space:]]*/[[:space:]]*$'; then
            robots_status="BLOCKS_ALL"
        fi
        # Pull the first Sitemap: directive if present, to check that
        # specific location instead of just guessing /sitemap.xml
        sitemap_url=$(echo "$robots_body" | grep -ioE '^[[:space:]]*sitemap:[[:space:]]*\S+' \
            | head -1 | sed -E 's/^[[:space:]]*[Ss]itemap:[[:space:]]*//')
    fi

    # Fall back to the conventional path if robots.txt didn't point
    # us anywhere (either robots.txt is missing, or it didn't declare
    # a Sitemap: directive — both are common and not themselves a
    # red flag).
    [ -z "${sitemap_url:-}" ] && sitemap_url="http://${domain}/sitemap.xml"

    sitemap_body=$(curl -s --max-time 8 -L -w "\n%{http_code}" \
        "$sitemap_url" 2>/dev/null || echo "ERR")
    sitemap_code=$(echo "$sitemap_body" | tail -1)
    sitemap_body=$(echo "$sitemap_body" | sed '$d')

    if [ "$sitemap_code" = "200" ] && [ -n "$sitemap_body" ]; then
        sitemap_status="OK"
        # Count <url> entries for a plain sitemap, or <sitemap> entries
        # for a sitemap INDEX (a sitemap that just lists other sitemaps
        # rather than URLs directly — common on larger sites). Report
        # whichever is actually present; an index with 0 <url> tags
        # isn't broken, it's just one level removed from the real count.
        # NOTE: grep -c counts matching LINES, not total matches — a
        # minified sitemap with many tags on one line would undercount
        # badly. grep -o | wc -l counts every individual match instead.
        url_count=$(echo "$sitemap_body" | grep -oE '<url>' | wc -l)
        if [ "${url_count:-0}" -eq 0 ]; then
            local sitemap_count
            sitemap_count=$(echo "$sitemap_body" | grep -oE '<sitemap>' | wc -l)
            if [ "${sitemap_count:-0}" -gt 0 ]; then
                sitemap_status="SITEMAP_INDEX"
                url_count="$sitemap_count"
            fi
        fi
    fi

    echo "${robots_status}|${sitemap_status}|${url_count}"
}

# ══════════════════════════════════════════════════════════════════
# OPTIMIZATION 4 — Merged anchors + foreign-anchor detection
# Was: api_anchors() and api_foreign_anchors() both called
# backlinks/anchors/live with identical payloads
# Now: ONE call, both analyses run on the same response
# ══════════════════════════════════════════════════════════════════
api_anchors_full() {
    local domain="$1"
    local r sc
    r=$(dfs_call "backlinks/anchors/live" \
        "[{\"target\":\"${domain}\",\"limit\":100,\"include_subdomains\":true}]" 2>/dev/null) || true
    check_abort && { echo "ERR|0|N/A|0|0|OK"; return 1; }
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    [ "$sc" != "20000" ] && { echo "ERR|0|N/A|0|0|OK"; return 0; }

    local fetched
    fetched=$(echo "$r" | jq -r '.tasks[0].result[0].items | length' 2>/dev/null || echo 0)
    [ "${fetched:-0}" -eq 0 ] && { echo "OK|0|N/A|0|0|OK"; return 0; }

    local total top_anchor top_bl second_bl
    total=$(echo "$r"      | jq -r '.tasks[0].result[0].total_count // 0' 2>/dev/null || true)
    top_anchor=$(echo "$r" | jq -r '.tasks[0].result[0].items[0].anchor // "N/A"' 2>/dev/null || true)
    top_anchor=$(sanitize_field "$top_anchor")
    top_bl=$(echo "$r"     | jq -r '.tasks[0].result[0].items[0].backlinks // 0' 2>/dev/null || true)
    second_bl=$(echo "$r"  | jq -r '.tasks[0].result[0].items[1].backlinks // 0' 2>/dev/null || true)

    local anc_flag="OK"
    if [ "${top_bl:-0}" -gt 0 ] && [ "${second_bl:-0}" -gt 0 ] 2>/dev/null; then
        local ratio=$(( top_bl * 100 / (top_bl + second_bl) ))
        [ "$ratio" -gt 70 ] 2>/dev/null && anc_flag="OVER_OPTIMISED"
    fi
    [ "$top_anchor" = "$domain" ] && anc_flag="SELF_REFERENTIAL"

    # Foreign-language check runs on the SAME items array — no 2nd call
    local anchors foreign=0 gambling_hit=0
    anchors=$(echo "$r" | jq -r '.tasks[0].result[0].items[]?.anchor // ""' 2>/dev/null || true)
    while IFS= read -r anchor; do
        [ -z "$anchor" ] && continue
        local len non_ascii ratio
        len=${#anchor}
        [ "$len" -eq 0 ] && continue
        non_ascii=$(printf '%s' "$anchor" | LC_ALL=C grep -o '[^[:print:][:space:]]' | wc -l)
        ratio=$(( non_ascii * 100 / len ))
        [ "$ratio" -gt 70 ] && (( foreign++ )) || true
        echo "$anchor" | grep -qE "华体会|博彩|赌场|彩票|казино|ставки" && (( gambling_hit++ )) || true
    done <<< "$anchors"

    local fa_pct=$(( foreign * 100 / fetched ))
    local fa_flag="OK"
    if [ "$gambling_hit" -gt 0 ]; then fa_flag="FOREIGN_GAMBLING_SPAM"
    elif [ "$fa_pct" -gt 30 ]; then fa_flag="HIGH_FOREIGN"
    elif [ "$fa_pct" -gt 10 ]; then fa_flag="SOME_FOREIGN"
    fi

    echo "${anc_flag}|${total}|${top_anchor}|${foreign}|${fa_pct}|${fa_flag}"
}

# ── CHECK 8: Spam referring domains ──────────────────────────────
api_spam_domains() {
    local domain="$1"
    local r sc
    r=$(dfs_call "backlinks/referring_domains/live" \
        "[{\"target\":\"${domain}\",\"limit\":50,\"order_by\":[\"backlinks_spam_score,desc\"],\"include_subdomains\":true}]" \
        2>/dev/null) || true
    check_abort && { echo "ERR|ERR|ERR|ERR"; return 1; }
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

# ── CHECK 12: Link velocity ───────────────────────────────────────
api_link_velocity() {
    local domain="$1"
    local r sc
    r=$(dfs_call "backlinks/timeseries_summary/live" \
        "[{\"target\":\"${domain}\",\"date_from\":\"$(date -d '2 years ago' +%Y-%m-%d 2>/dev/null || date -v-2y +%Y-%m-%d 2>/dev/null || echo '2023-01-01')\",\"date_to\":\"$(date +%Y-%m-%d)\",\"group_by\":\"month\",\"include_subdomains\":true}]" \
        2>/dev/null) || true
    check_abort && { echo "OK|0|0"; return 1; }
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    [ "$sc" != "20000" ] && { echo "OK|0|0"; return 0; }

    local counts
    counts=$(echo "$r" | jq -r '.tasks[0].result[0].items[]?.new_backlinks // 0' 2>/dev/null || true)
    [ -z "$counts" ] && { echo "OK|0|0"; return 0; }

    local max_month=0 total_bl=0
    while IFS= read -r n; do
        [[ "$n" =~ ^[0-9]+$ ]] || continue
        total_bl=$(( total_bl + n )) || true
        [ "$n" -gt "$max_month" ] && max_month="$n"
    done <<< "$counts"

    local flag="OK" spike_pct=0
    if [ "${total_bl:-0}" -gt 0 ] && [ "${max_month:-0}" -gt 0 ] 2>/dev/null; then
        spike_pct=$(( max_month * 100 / total_bl )) 2>/dev/null || true
        [ "$spike_pct" -gt 60 ] && flag="SPIKE"
        [ "$spike_pct" -gt 80 ] && flag="SEVERE_SPIKE"
    fi
    echo "${flag}|${max_month}|${spike_pct}"
}

# ── CHECK 13: Referring IP diversity ─────────────────────────────
api_ip_diversity() {
    local domain="$1"
    local r sc
    r=$(dfs_call "backlinks/referring_networks/live" \
        "[{\"target\":\"${domain}\",\"limit\":50,\"include_subdomains\":true}]" \
        2>/dev/null) || true
    check_abort && { echo "ERR|0|0"; return 1; }
    sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || echo 0)
    [ "$sc" != "20000" ] && { echo "ERR|0|0"; return 0; }

    local total_networks top_net_bl all_bl
    total_networks=$(echo "$r" | jq -r '.tasks[0].result[0].total_count // 0' 2>/dev/null || echo 0)
    top_net_bl=$(echo "$r" | jq -r '.tasks[0].result[0].items[0].backlinks // 0' 2>/dev/null || echo 0)
    all_bl=$(echo "$r" | jq -r '[.tasks[0].result[0].items[].backlinks // 0] | add // 0' 2>/dev/null || echo 0)

    local conc_pct=0 flag="OK"
    if [ "${all_bl:-0}" -gt 0 ] && [ "${top_net_bl:-0}" -gt 0 ] 2>/dev/null; then
        conc_pct=$(( top_net_bl * 100 / all_bl )) 2>/dev/null || true
        [ "$conc_pct" -gt 60 ] && flag="LOW_DIVERSITY"
        [ "$conc_pct" -gt 80 ] && flag="SINGLE_HOST"
    fi
    echo "${flag}|${total_networks}|${conc_pct}"
}

# ── Composite score calculator (unchanged logic, same as v6) ─────
calculate_score() {
    local idx_status="$1" dr="$2" bl="$3" spam_score="$4"
    local niche_status="$5" redir_status="$6" anc_flag="$7"
    local link_flag="$8" wb_age="${9}"
    local spd_count="${10}" velocity_flag="${11:-OK}"
    local foreign_flag="${12:-OK}" ip_flag="${13:-OK}"
    local domain="${14:-}"

    # TLD-relative age multiplier: the same number of years means
    # different things on different TLDs. Legacy TLDs (.com/.net/.org)
    # have existed since the early internet at huge volume, so simple
    # longevity is a weaker signal on its own — lots of junk domains
    # are old too. Newer/smaller gTLDs (.io, .co, .xyz, .app, etc.)
    # haven't existed nearly as long at scale, so a domain surviving
    # 5-10 years on one of those is comparatively more unusual and
    # gets weighted up. This is deliberately a small, conservative
    # multiplier — not a replacement for the underlying age tiers,
    # just context on top of them.
    local tld="" age_multiplier=100
    if [ -n "$domain" ]; then
        tld=$(echo "$domain" | grep -oE '\.[a-z]+$' | tr -d '.')
        case "$tld" in
            com|net|org) age_multiplier=100 ;;   # baseline, huge legacy volume
            io|co|xyz|app|dev|ai)  age_multiplier=130 ;;  # newer/smaller gTLDs, age means more
            *) age_multiplier=110 ;;             # everything else, mild bump
        esac
    fi

    local flags=""

    # ══════════════════════════════════════════════════════════════
    # AUTHORITY — rewards evidence of strength. Starts at 0, builds up.
    # DR, backlink volume, domain age, and niche consistency are all
    # genuinely independent positive signals, so additive bonuses are
    # appropriate here (unlike Spam Risk, where overlapping negative
    # signals from the SAME root cause used to triple-punish a domain).
    # ══════════════════════════════════════════════════════════════
    local authority=0
    # DR tiers steepened against real production data: across a real
    # 100-domain batch, almost no domains hit DR>=70 (the old top
    # tier), meaning the vast majority were stuck in the bottom of
    # Authority's range regardless of how strong their profile
    # actually was relative to typical PBN candidates. These tiers
    # reward the DR ranges domains in this space actually occupy.
    if [[ "$dr" =~ ^[0-9]+$ ]]; then
        if   [ "$dr" -ge 60 ]; then (( authority += 50 )) || true; flags+="HIGH_DR;"
        elif [ "$dr" -ge 30 ]; then (( authority += 35 )) || true; flags+="MED_DR;"
        elif [ "$dr" -ge 10 ]; then (( authority += 20 )) || true
        elif [ "$dr" -ge 1  ]; then (( authority += 8  )) || true
        fi
    fi
    if [[ "$bl" =~ ^[0-9]+$ ]]; then
        if   [ "$bl" -ge 10000 ]; then (( authority += 20 )) || true
        elif [ "$bl" -ge 1000  ]; then (( authority += 12 )) || true
        elif [ "$bl" -ge 100   ]; then (( authority += 6  )) || true
        fi
    fi
    if [[ "$wb_age" =~ ^[0-9]+$ ]]; then
        local age_bonus=0
        if   [ "$wb_age" -ge 10 ]; then age_bonus=20; flags+="OLD_DOMAIN;"
        elif [ "$wb_age" -ge 5  ]; then age_bonus=12
        elif [ "$wb_age" -ge 2  ]; then age_bonus=6
        fi
        if [ "$age_bonus" -gt 0 ]; then
            age_bonus=$(( age_bonus * age_multiplier / 100 ))
            (( authority += age_bonus )) || true
            [ "$age_multiplier" -gt 100 ] && flags+="TLD_AGE_BONUS;"
        fi
    fi
    [ "$niche_status" = "CONSISTENT" ] && { (( authority += 20 )) || true; }
    [ "$authority" -gt 100 ] && authority=100

    # ══════════════════════════════════════════════════════════════
    # SPAM RISK — penalizes evidence of badness. Starts at 100 (clean),
    # drops with each finding. index SPAM, raw spam%, spam referring
    # domains, and foreign-gambling anchors are all facets of the SAME
    # underlying "this domain looks spammy" signal, grouped together
    # so they compete within one 0-100 bucket instead of each
    # independently subtracting from one shared pool.
    # ══════════════════════════════════════════════════════════════
    local spam_risk=100
    [ "$idx_status" = "SPAM" ] && { (( spam_risk -= 100 )) || true; flags+="SPAM_CONTENT;"; }
    if [[ "$spam_score" =~ ^[0-9]+$ ]]; then
        if   [ "$spam_score" -gt 50 ]; then (( spam_risk -= 40 )) || true; flags+="HIGH_SPAM;"
        elif [ "$spam_score" -gt 30 ]; then (( spam_risk -= 25 )) || true; flags+="MED_SPAM;"
        elif [ "$spam_score" -gt 15 ]; then (( spam_risk -= 10 )) || true
        fi
    fi
    if [[ "$spd_count" =~ ^[0-9]+$ ]]; then
        if   [ "$spd_count" -gt 50 ]; then (( spam_risk -= 25 )) || true; flags+="MANY_SPAM_RD;"
        elif [ "$spd_count" -gt 20 ]; then (( spam_risk -= 15 )) || true
        elif [ "$spd_count" -gt 10 ]; then (( spam_risk -= 8  )) || true
        fi
    fi
    case "$foreign_flag" in
        FOREIGN_GAMBLING_SPAM) (( spam_risk -= 35 )) || true; flags+="FOREIGN_GAMBLING_SPAM;" ;;
        HIGH_FOREIGN)          (( spam_risk -= 10 )) || true; flags+="HIGH_FOREIGN_CONTENT;" ;;
    esac
    [ "$spam_risk" -lt 0 ] && spam_risk=0

    # ══════════════════════════════════════════════════════════════
    # LINK PROFILE — penalizes artificial-looking link patterns.
    # Starts at 100, drops with each finding. Link scheme ratio,
    # velocity spikes, IP diversity, and anchor-text patterns are all
    # different angles on "do these backlinks look organic or bought
    # in bulk", grouped so they don't bleed into Authority or Spam
    # Risk's buckets.
    # ══════════════════════════════════════════════════════════════
    local link_profile=100
    case "$link_flag" in
        LIKELY_SCHEME)      (( link_profile -= 40 )) || true; flags+="LINK_SCHEME;" ;;
        HIGH_CONCENTRATION) (( link_profile -= 15 )) || true; flags+="HIGH_LINK_CONC;" ;;
    esac
    case "$velocity_flag" in
        SEVERE_SPIKE) (( link_profile -= 35 )) || true; flags+="SEVERE_LINK_SPIKE;" ;;
        SPIKE)        (( link_profile -= 20 )) || true; flags+="LINK_SPIKE;" ;;
    esac
    case "$ip_flag" in
        SINGLE_HOST)   (( link_profile -= 30 )) || true; flags+="SINGLE_HOST_LINKS;" ;;
        LOW_DIVERSITY) (( link_profile -= 15 )) || true; flags+="LOW_IP_DIVERSITY;" ;;
    esac
    case "$anc_flag" in
        OVER_OPTIMISED)   (( link_profile -= 20 )) || true; flags+="OVER_OPTIMISED;" ;;
        SELF_REFERENTIAL) (( link_profile -= 25 )) || true; flags+="SELF_REFERENTIAL;" ;;
    esac
    [ "$link_profile" -lt 0 ] && link_profile=0

    # ══════════════════════════════════════════════════════════════
    # STABILITY — penalizes red flags about the site's CURRENT state.
    # Starts at 100. Being indexed is table stakes, not a bonus, so
    # CLEAN is neutral here — only NOT_INDEXED penalizes. This is the
    # other half of what index_status used to mean; SPAM now lives
    # entirely in Spam Risk above instead of mixing both meanings into
    # one case statement.
    # ══════════════════════════════════════════════════════════════
    local stability=100
    [ "$idx_status" = "NOT_INDEXED" ] && { (( stability -= 30 )) || true; flags+="NOT_INDEXED;"; }
    case "$redir_status" in
        REDIRECTS_AWAY) (( stability -= 50 )) || true; flags+="REDIRECTS_AWAY;" ;;
        CHAIN_TOO_LONG) (( stability -= 20 )) || true; flags+="REDIRECT_CHAIN;" ;;
    esac
    case "$niche_status" in
        INCONSISTENT) (( stability -= 20 )) || true; flags+="NICHE_INCONSISTENT;" ;;
        UNSTABLE)     (( stability -= 40 )) || true; flags+="NICHE_UNSTABLE;" ;;
    esac
    [ "$stability" -lt 0 ] && stability=0

    # ══ Combine — weighted, not equal-weight average ═══════════════
    # Spam Risk and Link Profile carry slightly more weight (30% each)
    # than Authority (30%) and Stability (10%) — note Authority was
    # RAISED from 20% back to 30% after real production data showed
    # 20% made it nearly invisible: across the entire realistic DR
    # range (0 to 400+), the final score only moved ~8 points with
    # everything else held constant, meaning domains with real
    # backlink authority and domains with none were landing in the
    # same grade. The original concern that motivated lowering
    # Authority in the first place — a high-Authority domain masking
    # bad Spam Risk/Link Profile findings (e.g. a link-scheme +
    # gambling-spam domain with massive DR) — is now handled by the
    # compounding severity penalty below, not by suppressing Authority's
    # base weight. Tested: the adversarial case still lands well under
    # the F threshold at these weights.
    local score=$(( (authority * 30 + spam_risk * 30 + link_profile * 30 + stability * 10) / 100 ))

    # ── Compounding severity penalty ────────────────────────────────
    # No single weighting scheme can make several independently severe
    # red flags average down to an F — that's the nature of averaging.
    # But 2+ severe flags firing TOGETHER is a pattern, not a
    # coincidence (a link-scheme domain that's ALSO running foreign
    # gambling spam anchors is worse than either alone), so apply an
    # extra multiplicative penalty per severe flag beyond the first.
    # This is not a hard disqualifier — a domain can still theoretically
    # claw back into a higher grade if other signals are strong enough,
    # it just makes severe combinations cost noticeably more than the
    # sum of their individual weighted contributions.
    local severe_count=0
    case "$flags" in *SPAM_CONTENT\;*)          (( severe_count++ )) || true ;; esac
    case "$flags" in *LINK_SCHEME\;*)           (( severe_count++ )) || true ;; esac
    case "$flags" in *FOREIGN_GAMBLING_SPAM\;*) (( severe_count++ )) || true ;; esac
    case "$flags" in *SINGLE_HOST_LINKS\;*)     (( severe_count++ )) || true ;; esac
    case "$flags" in *REDIRECTS_AWAY\;*)        (( severe_count++ )) || true ;; esac
    case "$flags" in *SEVERE_LINK_SPIKE\;*)     (( severe_count++ )) || true ;; esac
    case "$flags" in *NICHE_UNSTABLE\;*)        (( severe_count++ )) || true ;; esac

    if [ "$severe_count" -ge 2 ]; then
        # Each additional severe flag beyond the first multiplies the
        # score down by 30% — two severe flags = 70% of score, three =
        # 49%, four = ~34%. Compounds rather than stacks flatly, so it
        # scales smoothly instead of risking negative values on domains
        # with many flags, while still being aggressive enough that a
        # domain with 2+ genuinely severe findings reliably lands in F
        # territory rather than hovering at a misleadingly survivable D.
        local extra_severe=$(( severe_count - 1 ))
        local i=0
        while [ "$i" -lt "$extra_severe" ]; do
            score=$(( score * 70 / 100 ))
            (( i++ )) || true
        done
        flags+="MULTIPLE_SEVERE_FLAGS;"
    fi

    [ "$score" -lt 0   ] && score=0
    [ "$score" -gt 100 ] && score=100

    local grade
    if   [ "$score" -ge 75 ]; then grade="A"
    elif [ "$score" -ge 60 ]; then grade="B"
    elif [ "$score" -ge 45 ]; then grade="C"
    elif [ "$score" -ge 30 ]; then grade="D"
    else                            grade="F"
    fi

    [ "$idx_status" = "CLEAN" ] && flags+="CLEAN_INDEX;"

    echo "${score}|${grade}|${flags%;}|${authority}|${spam_risk}|${link_profile}|${stability}"
}

# ══════════════════════════════════════════════════════════════════
# Persistent cache — skip re-checking domains analyzed recently.
# Stores the exact same 41-field row that goes into the CSV, plus a
# checked_at timestamp. CACHE_DB and CACHE_MAX_AGE_DAYS are exported
# by pipeline.sh; if CACHE_DB is unset, every cache function becomes
# a clean no-op so the pipeline still works with caching disabled.
# Requires the `sqlite3` CLI — if it's not installed, cache_init()
# disables caching for the run rather than failing the whole pipeline.
# ══════════════════════════════════════════════════════════════════
cache_init() {
    [ -z "${CACHE_DB:-}" ] && return 0
    if ! command -v sqlite3 &>/dev/null; then
        warn "sqlite3 not found — caching disabled for this run (install sqlite3 to enable)"
        export CACHE_DB=""
        return 0
    fi
    sqlite3 "$CACHE_DB" "
        CREATE TABLE IF NOT EXISTS domain_cache (
            domain TEXT PRIMARY KEY,
            row TEXT NOT NULL,
            checked_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS domain_history (
            domain TEXT NOT NULL,
            checked_at INTEGER NOT NULL,
            score INTEGER,
            grade TEXT,
            authority INTEGER,
            spam_risk INTEGER,
            link_profile INTEGER,
            stability INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_history_domain ON domain_history(domain);
    " 2>/dev/null || warn "Failed to initialize cache DB — caching disabled for this run"
}

# Returns the cached row for $1 if present and fresher than
# CACHE_MAX_AGE_DAYS, otherwise prints nothing and returns 1.
cache_get() {
    local domain="$1"
    [ -z "${CACHE_DB:-}" ] && return 1
    local max_age_secs=$(( ${CACHE_MAX_AGE_DAYS:-7} * 86400 ))
    local now=$(date +%s)
    local cutoff=$(( now - max_age_secs ))
    local row
    row=$(sqlite3 -separator '|' "$CACHE_DB" \
        "SELECT row, checked_at FROM domain_cache WHERE domain = '${domain//\'/\'\'}' LIMIT 1;" 2>/dev/null)
    [ -z "$row" ] && return 1
    local cached_row cached_at
    IFS='|' read -r cached_row cached_at <<< "$row"
    [ -z "$cached_at" ] && return 1
    [ "$cached_at" -lt "$cutoff" ] 2>/dev/null && return 1
    echo "$cached_row"
    return 0
}

# Stores/updates the cache row for $1 (domain) with $2 (full CSV row).
cache_set() {
    local domain="$1" row="$2"
    [ -z "${CACHE_DB:-}" ] && return 0
    local now=$(date +%s)
    local escaped_row="${row//\'/\'\'}"
    local escaped_domain="${domain//\'/\'\'}"
    ( flock -x 9
      sqlite3 "$CACHE_DB" "
          INSERT INTO domain_cache (domain, row, checked_at)
          VALUES ('${escaped_domain}', '${escaped_row}', ${now})
          ON CONFLICT(domain) DO UPDATE SET row=excluded.row, checked_at=excluded.checked_at;
      " 2>/dev/null
    ) 9>"${CACHE_LCK:-/tmp/dhp_cache_lock}"
}

# Appends a lightweight history row (score/grade/sub-scores only, not
# the full CSV row) every time a domain is freshly checked. Unlike
# domain_cache (one row per domain, overwritten each time), this table
# is append-only — every check leaves a permanent trace, building a
# trend dataset over time. This is what makes trend_report.sh possible
# later: "has this domain's Spam Risk been climbing across checks" is
# a question domain_cache alone can never answer, since it only ever
# holds the most recent snapshot.
cache_record_history() {
    local domain="$1" score="$2" grade="$3" authority="$4" spam_risk="$5" link_profile="$6" stability="$7"
    [ -z "${CACHE_DB:-}" ] && return 0
    local now=$(date +%s)
    local escaped_domain="${domain//\'/\'\'}"
    ( flock -x 9
      sqlite3 "$CACHE_DB" "
          INSERT INTO domain_history (domain, checked_at, score, grade, authority, spam_risk, link_profile, stability)
          VALUES ('${escaped_domain}', ${now}, ${score:-0}, '${grade:-N/A}', ${authority:-0}, ${spam_risk:-0}, ${link_profile:-0}, ${stability:-0});
      " 2>/dev/null
    ) 9>"${CACHE_LCK:-/tmp/dhp_cache_lock}"
}

csv_write() { ( flock -x 9; echo "$1" >> "$REPORT" ) 9>"$RPT_LCK"; }

csv_update() {
    # $1 = domain to match (first CSV field), $2 = full replacement line
    # Uses awk instead of sed -i because anchor text / domain content
    # can contain pipes, slashes, or other characters that break sed's
    # delimiter — awk matches on the literal first field instead.
    #
    # Each call uses its own uniquely-named temp file (PID + random)
    # rather than a shared "$REPORT.tmp" path, eliminating any
    # possibility of concurrent workers colliding on the same temp file.
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
