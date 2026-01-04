# Wayback Machine Scanning Pipeline

## Overview

The DorkStrike scanner now uses a Wayback Machine CDX API-based pipeline instead of Google/Bing HTML parsing. This provides more reliable and comprehensive file discovery.

## Pipeline Architecture

```
[STAGE 1] SEARCH: Wayback CDX API
    ↓
    - Query Wayback Machine for target domain
    - Filter by file extensions (.env, .json, .sql, .bak, etc.)
    - Return list of archived URLs
    ↓
[STAGE 2] DNS VALIDATION
    ↓
    - Check DNS resolution for each URL
    - Filter out non-resolvable domains
    ↓
[STAGE 3] CONTENT FETCH
    ↓
    - Download content from URLs
    - Track download success/failure
    - Support JavaScript rendering (optional)
    ↓
[STAGE 4] CLASSIFICATION
    ↓
    - Classify resources into categories A-E
    - A: CONFIG/DATA FILES (Critical)
    - B: SOURCE/BUILD ARTIFACTS (High)
    - C: BACKUPS/DUMPS (High)
    - D: WEB PAGES (Low)
    - E: DOCS (Skip)
    ↓
[STAGE 5] PATTERN MATCH
    ↓
    - Apply regex patterns to downloaded content
    - NOT to search queries (important!)
    - Count all regex matches
    ↓
[STAGE 6] FINAL RESULTS
    ↓
    - Apply validation (if not RAW mode)
    - Return findings to UI
```

## Key Changes

### 1. Wayback CDX API Usage

**Before (Old Pipeline):**
- Generated Google/Bing dork queries
- Parsed HTML search results
- Applied regex to search snippets ❌
- Low reliability, many false positives

**After (New Pipeline):**
- Directly queries Wayback Machine CDX API
- Gets actual file URLs from archives
- Downloads real file content
- Applies regex to actual content ✓
- High reliability, real data

### 2. Extended File Extensions

The scanner now looks for these file types:

**Config Files:**
- .env, .json, .yml, .yaml, .conf, .ini, .cfg, .config, .properties

**Keys/Certificates:**
- .key, .pem, .crt, .p12, .pfx, .jks, .keystore

**Databases/Backups:**
- .db, .sqlite, .sqlite3, .sql, .dump, .backup, .bak, .old, .save

**Archives:**
- .zip, .tar, .tar.gz, .rar, .7z

**Logs/Temp:**
- .log, .tmp, .orig, .swp

### 3. RAW Mode

**Purpose:** Show ALL regex matches without validation filters.

**Behavior:**
- Bypasses entropy filtering
- Bypasses checksum validation
- Bypasses category restrictions
- Shows "dirty" results that may be false positives
- Marked as "RAW_MATCH" in verification column

**Use Cases:**
- Initial discovery phase
- When strict validation filters out valid results
- Debugging pattern matching
- Comprehensive security assessment

**STRICT Mode (default):**
- Applies all validation rules
- Only shows high-confidence findings
- Better signal-to-noise ratio
- Recommended for production use

### 4. Search Engine Deprecation

**Deprecated:**
- Google HTML parsing
- Bing HTML parsing
- DuckDuckGo HTML parsing
- Shodan integration (for file search)

**Kept for:**
- Direct URL scanning (custom URLs)
- Backward compatibility
- Future API-based integrations

## Configuration

### Enable RAW Mode

```python
scanner = DorkScanner(
    raw_mode=True  # Show all matches
)
```

Or in UI:
- Check "RAW Mode (показать все)" checkbox

### Wayback API Parameters

```python
async def search_wayback_archives(self, target, log_callback=None):
    # Uses these filters:
    - filter=original:.*\.{ext}  # File extension
    - filter=statuscode:200         # Successful responses
    - collapse=urlkey               # Deduplicate URLs
    - limit=100                    # Results per extension
```

### Concurrent Requests

```python
results = scanner.scan(
    target_domain,
    pattern_category,
    max_concurrent=10,  # Adjust based on rate limits
    progress_callback,
    log_callback,
    finding_callback
)
```

## Logging

The scanner provides detailed pipeline logging:

```
============================================================
SCAN STARTED: example.com
Pattern Category: ALL
Raw Mode: DISABLED
Verify API Keys: DISABLED
============================================================

[STAGE 1] SEARCH: Querying Wayback Machine for example.com...
Wayback: Scanning 20 file extensions for example.com...
Wayback: Found 15 .env files
Wayback: Found 23 .json files
Wayback: Total unique URLs found: 156

[STAGE 1] COMPLETE: Found 156 URLs total

[STAGE 2-3] FETCH & MATCH: Downloading content and analyzing patterns...
Concurrent threads: 10

[STAGE 2] DNS VALIDATION: 145 domains resolved
[STAGE 3] CONTENT FETCH: 132 downloads successful (10 failed)
[STAGE 4] CLASSIFICATION: A:45 B:23 C:38 D:26 E:0
[STAGE 5] PATTERN MATCH: 89 regex matches found
[STAGE 6] FINAL RESULTS: 34 findings reported

Pattern breakdown:
  - SECRETS: 18
  - CRYPTO: 8
  - VULNERABILITIES: 8

============================================================
SCAN COMPLETE: Duration 45.32s
Found 34 potential security findings
============================================================
```

## Troubleshooting

### No URLs Found

**Problem:** `[STAGE 1] COMPLETE: Found 0 URLs total`

**Solutions:**
1. Check if domain exists in Wayback Machine:
   ```bash
   curl "http://web.archive.org/cdx/search/cdx?url=example.com/*&output=json"
   ```
2. Try without subdomain prefix
3. Check network connectivity to web.archive.org

### All Downloads Failed

**Problem:** `[STAGE 3] CONTENT FETCH: 0 downloads successful`

**Solutions:**
1. Reduce concurrent threads
2. Check DNS resolution
3. Verify URLs are accessible
4. Check rate limiting

### No Regex Matches

**Problem:** `[STAGE 5] PATTERN MATCH: 0 regex matches found`

**Solutions:**
1. Enable RAW MODE to see all matches
2. Check if content is text-based
3. Verify pattern categories
4. Try scanning specific file extensions manually

### Too Many False Positives

**Problem:** Many low-confidence findings

**Solutions:**
1. Disable RAW MODE (use STRICT)
2. Verify API keys (if secrets found)
3. Review pattern categories
4. Filter by resource category

## Performance Optimization

### Rate Limiting

The Wayback CDX API may rate limit requests:
- Default: 10 concurrent threads
- Timeout: 15 seconds per extension request
- Auto-wait on HTTP 429 responses

### Caching

DNS resolution is cached (300s TTL) to improve performance.

### Memory Usage

Findings are sent to UI immediately to avoid memory buildup.

## Security Considerations

1. **Never expose credentials** in logs or UI output
2. **Verify API keys** before assuming they're valid
3. **Handle sensitive data** according to your security policy
4. **Use RAW MODE** only in controlled environments

## Future Enhancements

- [ ] GitHub API integration for repository scanning
- [ ] S3 bucket enumeration
- [ ] Cloud storage discovery
- [ ] API-based Shodan integration
- [ ] Real-time findings export
- [ ] Machine learning validation
