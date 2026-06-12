#!/bin/bash
# lib.sh — single library: logging, proxy, API, report

R='\033[0;91m' G='\033[0;92m' Y='\033[0;93m' B='\033[0;94m' W='\033[1m' N='\033[0m'

log()  { echo -e "${B}[$(date '+%H:%M:%S')]${N} $1" | tee -a "$LOG" >&2; }
ok()   { echo -e "${G}[$(date '+%H:%M:%S')] ✓${N} $1" | tee -a "$LOG" >&2; }
warn() { echo -e "${Y}[$(date '+%H:%M:%S')] ⚠${N} $1" | tee -a "$LOG" >&2; }
err()  { echo -e "${R}[$(date '+%H:%M:%S')] ✗${N} $1" | tee -a "$LOG" >&2; }

proxy_init() {
    local count=$(grep -c '\S' "$PROXY_FILE" 2>/dev/null || true)
    [ "$count" -eq 0 ] && { err "No proxies in $PROXY_FILE"; exit 1; }
    echo "0" > "$PROXY_CTR"
    log "Loaded $count proxies"
    echo "$count"
}

proxy_get() {
    local n="$1"
    ( flock -x 9
      local i=$(cat "$PROXY_CTR" 2>/dev/null || echo 0)
      [[ "$i" =~ ^[0-9]+$ ]] || i=0
      local p=$(grep '\S' "$PROXY_FILE" | sed -n "$((i+1))p")
      echo $(( (i+1) % n )) > "$PROXY_CTR"
      [ "$p" = "direct" ] && echo "" || echo "$p"
    ) 9>"$PROXY_LCK"
}

api_backlinks() {
    local domain="$1" proxy="$2"
    local pflag=""; [ -n "$proxy" ] && pflag="-x http://$proxy"
    for i in $(seq 1 "${MAX_RETRIES:-3}"); do
        local r
        r=$(curl -s --max-time "${TIMEOUT:-10}" $pflag \
            -X POST "https://api.dataforseo.com/v3/backlinks/summary/live" \
            -H "Authorization: Basic $DATAFORSEO_TOKEN" \
            -H "Content-Type: application/json" \
            -d "[{\"target\":\"$domain\",\"include_subdomains\":true}]" 2>/dev/null || true)
        local sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || true)
        [ "$sc" = "20000" ] && {
            echo "$r" | jq -r '.tasks[0].result[0] | "\(.rank//0)|\(.backlinks//0)|\(.referring_domains//0)|\(.backlinks_spam_score//0)"' 2>/dev/null
            return 0
        }
        warn "Attempt $i failed for $domain: $(echo "$r" | jq -r '.tasks[0].status_message//"unknown"' 2>/dev/null || true)"
        sleep "${RETRY_DELAY:-2}"
    done
    echo "ERR|ERR|ERR|ERR"; return 1
}

api_index() {
    local domain="$1"
    local r
    r=$(curl -s --max-time "${TIMEOUT:-15}" \
        -X POST "https://api.dataforseo.com/v3/serp/google/organic/live/advanced" \
        -H "Authorization: Basic $DATAFORSEO_TOKEN" \
        -H "Content-Type: application/json" \
        -d "[{\"keyword\":\"site:$domain\",\"location_name\":\"United States\",\"language_name\":\"English\",\"depth\":10}]" \
        2>/dev/null || true)
    local sc=$(echo "$r" | jq -r '.tasks[0].status_code // 0' 2>/dev/null || true)
    [ "$sc" != "20000" ] && { echo "ERR|0"; return 1; }
    local pages=$(echo "$r" | jq -r '.tasks[0].result[0].total_count // 0' 2>/dev/null || true)
    local content=$(echo "$r" | jq -r '.tasks[0].result[0].items[]? | select(.type=="organic") | "\(.title//"") \(.description//"")"' 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
    local status="NOT_INDEXED"
    if [ "${pages:-0}" -gt 0 ] 2>/dev/null; then
        echo "$content" | grep -qiE "casino|poker|viagra|pharmacy|porn|gambling|slots|crypto|hack|torrent" \
            && status="SPAM" || status="CLEAN"
    fi
    echo "$status|$pages"
}

csv_write()  { ( flock -x 9; echo "$1" >> "$REPORT" ) 9>"$RPT_LCK"; }
csv_update() { ( flock -x 9; sed -i "s|$1|$2|" "$REPORT" ) 9>"$RPT_LCK"; }
