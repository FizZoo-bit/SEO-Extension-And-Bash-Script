# DataForSEO Backlink Checker
# Bash port of the Go architecture — parallel, retry-safe, proxy-rotating

## Setup

### 1. Install dependencies
```bash
# Ubuntu/Debian
sudo apt install jq bc curl

# Mac
brew install jq bc curl
```

### 2. Set your DataForSEO token
```bash
# Generate base64 token from your credentials
echo -n "your@email.com:yourpassword" | base64

# Add to ~/.bashrc
export DATAFORSEO_TOKEN="your_base64_token_here"

# Reload
source ~/.bashrc
```

### 3. Add your domains
```
# domains.txt — one per line, blank lines and # comments ignored
lemonde.fr
bbc.com
# nytimes.com  ← commented out, will be skipped
```

### 4. Add your proxies
```
# proxies.txt — format: user:password@host:port
user1:pass1@proxy1.host.com:8080
user2:pass2@proxy2.host.com:8080
```

### 5. Make executable
```bash
chmod +x checker.sh
```

---

## Usage

```bash
# Basic run
./checker.sh

# Custom files
./checker.sh -d my_domains.txt -p my_proxies.txt

# 10 parallel workers instead of 5
./checker.sh -j 10

# More retries
./checker.sh -r 5

# All options
./checker.sh -d domains.txt -p proxies.txt -j 5 -r 3
```

---

## Output

### Terminal
```
[08:14:22] INFO  Starting DataForSEO Backlink Checker
[08:14:22] INFO  Loaded 5 domains
[08:14:23] INFO  Launching 5 parallel workers...

  ************ ---> bbc.com <--- ************

  Domain Rating:     91
  Backlinks:         4823901
  Referring Domains: 142837
  ----------------------------------------------------
```

### CSV report (saved to reports/)
```
domain,domain_rank,backlinks,referring_domains,dofollow_backlinks,dofollow_domains,spam_score,status
bbc.com,91,4823901,142837,3901234,98231,2,OK
lemonde.fr,78,891203,31029,710293,24019,1,OK
```

### Final summary
```
═══════════════════════════════════════
  FINAL REPORT
═══════════════════════════════════════
  Domains processed: 5
  Successful:        5
  Failed:            0
  Bandwidth used:    0.42MB (432KB)
  Report saved to:   ./reports/backlinks_20260611_081422.csv
═══════════════════════════════════════
```

---

## Architecture — Go Patterns Translated to Bash

| Go concept          | Bash equivalent                        |
|---------------------|----------------------------------------|
| goroutines          | xargs -P (parallel subprocesses)       |
| sync.WaitGroup      | xargs blocks until all workers done    |
| semaphore (chan)     | xargs -P N limits concurrency          |
| sync.Mutex          | flock on temp lockfiles                |
| round-robin proxy   | shared counter in temp file + flock    |
| traffic tracking    | shared byte counter + flock            |
| retry loop          | for attempt in $(seq 1 $MAX_RETRIES)   |
| defer cleanup       | trap cleanup EXIT                      |
| structured types    | pipe-delimited strings + cut           |
| package separation  | lib/log.sh lib/proxy.sh lib/api.sh     |

---

## File Structure

```
backlink_checker/
├── checker.sh        ← main orchestrator
├── domains.txt       ← input domains
├── proxies.txt       ← proxy list
├── lib/
│   ├── log.sh        ← colored logging
│   ├── proxy.sh      ← round-robin rotation + mutex
│   ├── api.sh        ← DataForSEO calls + retry + traffic
│   └── report.sh     ← CSV output + summary
└── reports/          ← output files (auto-created)
    ├── run_*.log
    └── backlinks_*.csv
```
