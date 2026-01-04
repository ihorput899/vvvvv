# scanner.py - Core scanning engine for DorkStrike PRO

import asyncio
import aiohttp
import aiodns
import requests
import re
import time
import threading
import random
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from bs4 import BeautifulSoup
from patterns import DorkPatterns, validate_crypto_pattern, validate_secret_pattern, calculate_shannon_entropy, verify_api_key
from fake_useragent import UserAgent

# Resource classification categories
RESOURCE_CATEGORIES = {
    'A': 'CONFIG/DATA FILES',
    'B': 'SOURCE/BUILD ARTIFACTS', 
    'C': 'BACKUPS/DUMPS',
    'D': 'WEB PAGES',
    'E': 'DOCS'
}

# Priority mapping for UI display
CATEGORY_PRIORITY = {
    'A': 'CRITICAL',
    'B': 'HIGH',
    'C': 'HIGH',
    'D': 'LOW',
    'E': 'SKIP'
}

# Extensions by category
CATEGORY_EXTENSIONS = {
    'A': ['.env', '.json', '.yml', '.yaml', '.ini', '.conf', '.cnf', '.sql', '.dump', '.bak', '.old', '.zip', '.tar.gz'],
    'B': ['.js.map', '.py', '.php', '.rb', '.go'],
    'C': ['.backup', '.dump', '.sql', '.archive', '.tar', '.tar.gz', '.zip', '.db'],
    'D': ['.html', '.htm'],
}

# URL path blacklist (Category E)
BLACKLIST_URLS = [
    "/docs",
    "/readme", 
    "/swagger",
    "/postman",
    "/wiki",
    "/faq",
    "/help",
    "/examples",
]

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

class DorkScanner:
    def __init__(self, proxies=None, search_engines=None, use_js_rendering=False, verify_api_keys=False, strictness="medium", depth=3, custom_dorks=None, raw_mode=False, delay=5.0, dns_verify=True, proxy_type="SOCKS5", ua_rotate=True):
        self.patterns = DorkPatterns()
        self.stop_event = threading.Event()
        self.session = requests.Session()
        self.proxies = proxies or []
        self.ua = UserAgent()
        self.search_engines = search_engines or ['google']  # Default to Google
        self.use_js_rendering = use_js_rendering and PLAYWRIGHT_AVAILABLE
        self.verify_api_keys = verify_api_keys
        self.dns_resolver = None
        self.strictness = strictness.lower()
        self.depth = depth
        self.request_count = 0
        self.custom_dorks = custom_dorks or []
        self.raw_mode = raw_mode
        self.delay = delay
        self.dns_verify = dns_verify
        self.proxy_type = proxy_type
        self.ua_rotate = ua_rotate
        
        # Resource classification tracking
        self.resource_stats = {category: 0 for category in RESOURCE_CATEGORIES.keys()}
        self.dns_passed_count = 0
        self.download_success_count = 0
        self.regex_match_count = 0
        self.findings_count = 0
        self.total_urls = 0
        self.target_domain = ""

    def classify_resource(self, url, content_type=""):
        """
        Classify a URL into resource categories A-E.
        
        Returns: dict with 'category' and 'priority' keys
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Check URL blacklist first (Category E - always skip)
        for blacklist_item in BLACKLIST_URLS:
            if blacklist_item.lower() in path:
                return {'category': 'E', 'priority': CATEGORY_PRIORITY['E']}
        
        # Check extensions by priority
        url_lower = url.lower()
        
        # Category A: CONFIG/DATA FILES
        for ext in CATEGORY_EXTENSIONS['A']:
            if url_lower.endswith(ext):
                return {'category': 'A', 'priority': CATEGORY_PRIORITY['A']}
        
        # Category B: SOURCE/BUILD ARTIFACTS  
        for ext in CATEGORY_EXTENSIONS['B']:
            if url_lower.endswith(ext):
                return {'category': 'B', 'priority': CATEGORY_PRIORITY['B']}
        
        # Category C: BACKUPS/DUMPS
        for ext in CATEGORY_EXTENSIONS['C']:
            if url_lower.endswith(ext):
                return {'category': 'C', 'priority': CATEGORY_PRIORITY['C']}
        
        # Category D: WEB PAGES
        for ext in CATEGORY_EXTENSIONS['D']:
            if url_lower.endswith(ext):
                return {'category': 'D', 'priority': CATEGORY_PRIORITY['D']}
        
        # Check for backup/dump paths even without specific extensions
        if any(keyword in path for keyword in ['backup', 'dump', 'db', 'export', 'archive']):
            return {'category': 'C', 'priority': CATEGORY_PRIORITY['C']}
        
        # Check content type as fallback
        if content_type:
            content_type = content_type.lower()
            if 'text/html' in content_type:
                return {'category': 'D', 'priority': CATEGORY_PRIORITY['D']}
        
        # Default to WEB PAGES (D) if no clear classification
        return {'category': 'D', 'priority': CATEGORY_PRIORITY['D']}

    def is_url_blacklisted(self, url):
        """Check if URL is in blacklist (Category E)"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for blacklist_item in BLACKLIST_URLS:
            if blacklist_item.lower() in path:
                return True
        return False

    def stop_scan(self):
        self.stop_event.set()

    async def scan_async(self, target_domain, pattern_category, max_concurrent, progress_callback, log_callback, finding_callback):
        """Async version of scan method overhauled for Wayback Pipeline"""
        start_time = time.time()
        self.target_domain = target_domain

        log_callback("="*60)
        log_callback(f"SCAN STARTED: {target_domain}")
        log_callback(f"Pattern Category: {pattern_category}")
        log_callback(f"Raw Mode: {'ENABLED' if self.raw_mode else 'DISABLED'}")
        log_callback(f"Verify API Keys: {'ENABLED' if self.verify_api_keys else 'DISABLED'}")
        log_callback("="*60)

        log_callback(f"\n[STAGE 1] SEARCH: Querying Wayback Machine for {target_domain}...")

        # SEARCH STAGE - Use Wayback CDX API
        found_urls = await self.search_wayback_archives(target_domain, log_callback)

        # Also include any custom dorks if they look like direct URLs
        custom_urls = []
        for dork in self.custom_dorks:
            if dork.startswith("http"):
                 url = dork.replace("{target}", target_domain)
                 custom_urls.append(url)

        if custom_urls:
            log_callback(f"[STAGE 1] Adding {len(custom_urls)} custom URLs")
            found_urls.extend(custom_urls)

        found_urls = list(set(found_urls))
        self.total_urls = len(found_urls)
        total_urls = self.total_urls

        log_callback(f"[STAGE 1] COMPLETE: Found {total_urls} URLs total")

        results = {
            'total_urls': total_urls,
            'findings_count': 0,
            'pattern_breakdown': {},
            'duration': 0,
            'avg_response_time': 0,
            'dns_passed': 0,
            'download_success': 0,
            'regex_matches': 0
        }

        findings = []
        response_times = []

        # STAGE 2 & 3: FETCH AND MATCH
        log_callback(f"\n[STAGE 2-3] FETCH & MATCH: Downloading content and analyzing patterns...")
        log_callback(f"Concurrent threads: {max_concurrent}")

        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(max_concurrent)

        # Create aiohttp session with connector settings
        connector = aiohttp.TCPConnector(limit=max_concurrent, ttl_dns_cache=300)
        timeout = aiohttp.ClientTimeout(total=20, connect=10)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            completed = 0

            for url in found_urls:
                if self.stop_event.is_set():
                    break

                # We pass "ALL" as pattern_name to scan for all patterns in the category
                task = asyncio.create_task(self.scan_url_async(session, (url, "ALL", pattern_category), pattern_category, semaphore, log_callback))
                tasks.append(task)

                # Process completed tasks in batches to update progress
                if len(tasks) >= max_concurrent:
                    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    tasks = list(pending)

                    for task in done:
                        try:
                            url_findings, response_time = task.result()
                            response_times.append(response_time)
                            findings.extend(url_findings)

                            for finding in url_findings:
                                finding_callback(finding['type'], finding['pattern'], finding['url'], finding['match'], finding.get('verification', 'Format valid'))
                                results['findings_count'] += 1
                                self.findings_count += 1

                                pattern_type = finding['type']
                                if pattern_type not in results['pattern_breakdown']:
                                    results['pattern_breakdown'][pattern_type] = 0
                                results['pattern_breakdown'][pattern_type] += 1

                        except Exception as e:
                            log_callback(f"Error processing task: {str(e)}")

                        completed += 1
                        progress = (completed / total_urls) * 100 if total_urls > 0 else 100
                        progress_callback(progress)

            # Process remaining tasks
            if tasks:
                done, _ = await asyncio.wait(tasks)
                for task in done:
                    try:
                        url_findings, response_time = task.result()
                        response_times.append(response_time)
                        findings.extend(url_findings)

                        for finding in url_findings:
                            finding_callback(finding['type'], finding['pattern'], finding['url'], finding['match'], finding.get('verification', 'Format valid'))
                            results['findings_count'] += 1
                            self.findings_count += 1

                            pattern_type = finding['type']
                            if pattern_type not in results['pattern_breakdown']:
                                results['pattern_breakdown'][pattern_type] = 0
                            results['pattern_breakdown'][pattern_type] += 1

                    except Exception as e:
                        log_callback(f"Error processing final task: {str(e)}")

                    completed += 1
                    progress = (completed / total_urls) * 100 if total_urls > 0 else 100
                    progress_callback(progress)

        results['duration'] = time.time() - start_time
        if response_times:
            results['avg_response_time'] = sum(response_times) / len(response_times)

        # Update results with pipeline stats
        results['dns_passed'] = self.dns_passed_count
        results['download_success'] = self.download_success_count
        results['regex_matches'] = self.regex_match_count
        results['resource_stats'] = self.resource_stats

        # Log summary stages
        log_callback(f"\n[STAGE 2] DNS VALIDATION: {self.dns_passed_count} domains resolved")
        log_callback(f"[STAGE 3] CONTENT FETCH: {self.download_success_count} downloads successful ({total_urls - self.download_success_count} failed)")

        # Log resource classification summary (Stage 4)
        resource_summary = " | ".join([f"{cat}:{RESOURCE_CATEGORIES[cat][:8]}:{count}" for cat, count in self.resource_stats.items()])
        log_callback(f"[STAGE 4] CLASSIFICATION: {resource_summary}")

        log_callback(f"[STAGE 5] PATTERN MATCH: {self.regex_match_count} regex matches found")
        log_callback(f"[STAGE 6] FINAL RESULTS: {results['findings_count']} findings reported")

        # Pattern breakdown
        if results['pattern_breakdown']:
            log_callback(f"\nPattern breakdown:")
            for pattern_type, count in results['pattern_breakdown'].items():
                log_callback(f"  - {pattern_type}: {count}")

        log_callback(f"\n{'='*60}")
        log_callback(f"SCAN COMPLETE: Duration {results['duration']:.2f}s")
        log_callback(f"Found {results['findings_count']} potential security findings")
        log_callback(f"{'='*60}")

        return results

    def scan(self, target_domain, pattern_category, max_concurrent, progress_callback, log_callback, finding_callback):
        """Main scan method - now uses asyncio internally"""
        self.stop_event.clear()

        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            # Run the async scan
            results = loop.run_until_complete(
                self.scan_async(target_domain, pattern_category, max_concurrent, progress_callback, log_callback, finding_callback)
            )
            return results
        finally:
            loop.close()

    def generate_dork_urls(self, target_domain, pattern_category):
        """
        Generate dork URLs for scanning.
        NOTE: This method is deprecated for remote scanning.
        Use search_wayback_archives() instead for the new pipeline.
        Only custom URLs are now supported.
        """
        dork_urls = []

        # Only process custom dorks that are direct URLs
        if self.custom_dorks:
            for custom_dork in self.custom_dorks:
                # Replace {target} placeholder with actual domain
                url = custom_dork.replace("{target}", target_domain)
                if url.startswith("http://") or url.startswith("https://"):
                    dork_urls.append((url, "Custom URL", "CUSTOM"))

        return dork_urls

    def _generate_search_url(self, engine, query):
        """
        Generate search URL for different engines.

        DEPRECATED: This method is no longer used for the main scanning pipeline.
        The scanner now uses Wayback Machine CDX API via search_wayback_archives().
        This method is kept for backward compatibility only.
        """
        query_encoded = query.replace(' ', '+')

        if engine == 'google':
            return f"https://www.google.com/search?q={query_encoded}&num=100"
        elif engine == 'duckduckgo':
            return f"https://duckduckgo.com/?q={query_encoded}&ia=web"
        elif engine == 'bing':
            return f"https://www.bing.com/search?q={query_encoded}&count=50"
        elif engine == 'shodan':
            # Shodan uses different syntax
            return f"https://www.shodan.io/search?query={query_encoded}"
        elif engine == 'wayback':
            # Wayback Machine CDX API
            return f"https://web.archive.org/cdx/search/cdx?url={query_encoded}&output=json"
        return None

    async def search_wayback_archives(self, target, log_callback=None):
        """
        Поиск архивных URL через CDX API (Wayback Machine).
        Ищем файлы по расширению для конкретного домена.
        """
        found_urls = []
        # Extended list of sensitive file extensions
        extensions = [
            "env", "json", "txt", "sql", "bak", "yml", "yaml", "conf",
            "key", "pem", "crt", "p12", "pfx", "jks", "keystore",
            "db", "sqlite", "sqlite3", "dump", "backup",
            "zip", "tar", "tar.gz", "rar", "7z",
            "log", "old", "save", "tmp", "orig", "swp",
            "ini", "cfg", "config", "properties"
        ]

        if log_callback:
            log_callback(f"Wayback: Scanning {len(extensions)} file extensions for {target}...")

        async with aiohttp.ClientSession() as session:
            for ext in extensions:
                if self.stop_event.is_set():
                    break

                # CDX API запрос: ищем файлы с расширением на целевом домене
                # Using multiple filters to get relevant results
                url = (
                    f"http://web.archive.org/cdx/search/cdx?url={target}/*"
                    f"&filter=original:.*\\.{ext}"
                    f"&filter=statuscode:200"
                    f"&output=json"
                    f"&collapse=urlkey"
                    f"&limit=100"
                )

                try:
                    async with session.get(url, timeout=15) as response:
                        if response.status == 200:
                            data = await response.json()
                            # Пропускаем заголовок [["urlkey", "timestamp", "original", "mimetype", "statuscode", ...]]
                            if len(data) > 1:
                                ext_count = 0
                                for item in data[1:]:
                                    if len(item) >= 3:
                                        original_url = item[2]
                                        found_urls.append(original_url)
                                        ext_count += 1
                                if log_callback and ext_count > 0:
                                    log_callback(f"Wayback: Found {ext_count} .{ext} files")
                        elif response.status == 429:
                            if log_callback:
                                log_callback(f"Wayback: Rate limited, waiting...")
                            await asyncio.sleep(2)

                except asyncio.TimeoutError:
                    if log_callback:
                        log_callback(f"Wayback: Timeout for .{ext} files")
                except Exception as e:
                    if log_callback:
                        log_callback(f"Wayback error ({ext}): {e}")

        # Deduplicate URLs
        found_urls = list(set(found_urls))
        if log_callback:
            log_callback(f"Wayback: Total unique URLs found: {len(found_urls)}")
        return found_urls

    async def check_dns_resolution(self, domain):
        """Check if domain resolves to IP addresses"""
        try:
            if not self.dns_resolver:
                self.dns_resolver = aiodns.DNSResolver()
            result = await self.dns_resolver.query(domain, 'A')
            return len(result) > 0
        except:
            return False

    def get_fresh_user_agent(self):
        """Get a fresh user agent, rotating frequently"""
        self.request_count += 1
        try:
            return self.ua.random
        except:
            # Fallback user agents
            fallback_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
            ]
            return fallback_agents[self.request_count % len(fallback_agents)]

    def render_page_with_js(self, url):
        """Render page with JavaScript using Playwright"""
        if not self.use_js_rendering or not PLAYWRIGHT_AVAILABLE:
            return None

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent=self.ua.random,
                    viewport={'width': 1920, 'height': 1080}
                )
                page = context.new_page()

                # Set timeout and navigate
                page.goto(url, wait_until="networkidle", timeout=30000)

                # Wait a bit for dynamic content
                page.wait_for_timeout(2000)

                # Get the rendered HTML
                html_content = page.content()

                browser.close()
                return html_content
        except Exception as e:
            print(f"JS rendering failed for {url}: {e}")
            return None

    async def scan_url_async(self, session, url_data, pattern_category, semaphore, log_callback=None):
        """Async version of scan_url with DNS check"""
        url, pattern_name, category = url_data
        start_time = time.time()

        async with semaphore:  # Limit concurrent requests
            try:
                # Extract domain for DNS check
                parsed = urlparse(url)
                domain = parsed.netloc

                # Check DNS resolution first
                if not await self.check_dns_resolution(domain):
                    if log_callback:
                        log_callback(f"  [DNS FAIL] {url}")
                    return [], time.time() - start_time

                self.dns_passed_count += 1

                # Use JS rendering if enabled
                html_content = None
                if self.use_js_rendering:
                    # Run JS rendering in thread pool since Playwright is sync
                    loop = asyncio.get_event_loop()
                    html_content = await loop.run_in_executor(None, self.render_page_with_js, url)
                    if html_content:
                        self.download_success_count += 1
                    else:
                        if log_callback:
                            log_callback(f"Download failed: JS rendering returned no content for {url}")
                        return [], time.time() - start_time
                else:
                    # Use aiohttp for regular requests
                    headers = {'User-Agent': self.get_fresh_user_agent()}
                    timeout = aiohttp.ClientTimeout(total=10)

                    try:
                        async with session.get(url, headers=headers, timeout=timeout) as response:
                            if response.status == 200:
                                html_content = await response.text()
                                self.download_success_count += 1
                            else:
                                if log_callback:
                                    log_callback(f"Download failed: status {response.status} for {url}")
                                return [], time.time() - start_time
                    except Exception as e:
                        if log_callback:
                            log_callback(f"Download failed: {str(e)} for {url}")
                        return [], time.time() - start_time

                if html_content:
                    # Run analysis in thread pool since it's CPU-bound
                    loop = asyncio.get_event_loop()
                    result_tuple = await loop.run_in_executor(None, self.analyze_response, html_content, url, pattern_name, category)

                    # analyze_response now returns (findings, skip_reason)
                    if isinstance(result_tuple, tuple) and len(result_tuple) == 2:
                        findings, skip_reason = result_tuple
                    else:
                        # Backward compatibility - old return format (shouldn't happen but handle anyway)
                        findings = result_tuple if result_tuple is not None else []
                        skip_reason = None

                    # Log skip reasons
                    if skip_reason and log_callback:
                        log_callback(skip_reason)

                    return findings, time.time() - start_time
                else:
                    return [], time.time() - start_time

            except Exception:
                return [], time.time() - start_time

    def scan_url(self, url_data, pattern_category):
        """Scan a single dork URL with optional JS rendering"""
        url, pattern_name, category = url_data
        start_time = time.time()

        try:
            html_content = None

            # Try JS rendering first if enabled
            if self.use_js_rendering:
                html_content = self.render_page_with_js(url)
                response_time = time.time() - start_time
            else:
                # Fallback to regular requests
                if self.proxies:
                    proxy = random.choice(self.proxies)
                    self.session.proxies = {'http': proxy, 'https': proxy}
                self.session.headers['User-Agent'] = self.ua.random
                time.sleep(random.uniform(self.delay, self.delay + 8))
                response = self.session.get(url, timeout=10)
                response_time = time.time() - start_time

                if response.status_code == 200:
                    html_content = response.text
                else:
                    return [], response_time

            if html_content:
                result_tuple = self.analyze_response(html_content, url, pattern_name, category)
                if isinstance(result_tuple, tuple) and len(result_tuple) == 2:
                    findings, skip_reason = result_tuple
                else:
                    findings = result_tuple
                return findings, response_time
            else:
                return [], response_time

        except Exception:
            return [], time.time() - start_time

    def analyze_response(self, html_content, url, pattern_name, category):
        """Analyze the HTML content for patterns with validation and resource classification."""
        findings = []
        skip_reason = None

        # Check domain if target_domain is set
        if self.target_domain and "://" in url:
            parsed_url = urlparse(url)
            if self.target_domain not in parsed_url.netloc:
                skip_reason = f"URL rejected: external domain ({parsed_url.netloc})"
                return findings, skip_reason

        # Classify the resource
        resource = self.classify_resource(url)
        resource_category = resource['category']

        # Update resource statistics
        self.resource_stats[resource_category] += 1

        # Skip if URL is blacklisted (Category E)
        if resource_category == 'E':
            skip_reason = f"URL rejected: blacklist ({url})"
            return findings, skip_reason

        if category == "ALL":
            categories_to_check = ["CRYPTO", "SECRETS", "VULNERABILITIES"]
        else:
            categories_to_check = [category]

        for cat in categories_to_check:
            patterns = self.patterns.get_patterns(cat)

            patterns_to_check = {}
            if pattern_name == "ALL" or pattern_name == "Custom Dork" or pattern_name == "CUSTOM":
                patterns_to_check = patterns
            elif pattern_name in patterns:
                patterns_to_check = {pattern_name: patterns[pattern_name]}

            for p_name, pattern_data in patterns_to_check.items():
                regex_patterns = pattern_data.get('regex', [])
                allow_categories = pattern_data.get('allow_categories', ['A', 'B', 'C'])  # Default to A/B/C
                deny_categories = pattern_data.get('deny_categories', ['D', 'E'])

                # Check if pattern is allowed for this resource category
                # In RAW MODE we bypass category filtering
                if not self.raw_mode:
                    if resource_category not in allow_categories:
                        continue

                    if resource_category in deny_categories:
                        continue

                for regex in regex_patterns:
                    try:
                        matches = re.findall(regex, html_content, re.IGNORECASE | re.MULTILINE)
                        for match in matches:
                            self.regex_match_count += 1

                            # Handle tuple matches from regex groups
                            if isinstance(match, tuple):
                                # Use the last captured group (usually the actual value)
                                match_str = str(match[-1])[:100] if match[-1] else str(match[0])[:100]
                            else:
                                match_str = str(match)[:100]  # Limit match length

                            # Apply validation based on category
                            is_valid = True
                            verification_status = "Format valid"

                            if cat == "CRYPTO":
                                is_valid, verification_status = validate_crypto_pattern(p_name, match_str, self.raw_mode)
                            elif cat == "SECRETS":
                                is_valid, verification_status = validate_secret_pattern(p_name, match_str, self.raw_mode)

                                # Additional API verification for supported services
                                if is_valid and self.verify_api_keys and cat == "SECRETS" and not self.raw_mode:
                                    # Run async verification in current thread
                                    try:
                                        loop = asyncio.new_event_loop()
                                        asyncio.set_event_loop(loop)
                                        verified, status = loop.run_until_complete(
                                            verify_api_key(p_name, match_str)
                                        )
                                        loop.close()

                                        if verified:
                                            verification_status = f"Live verified: {status}"
                                        else:
                                            verification_status = f"Live check failed: {status}"
                                            is_valid = False  # Mark as invalid if live check fails
                                    except Exception as e:
                                        verification_status = f"Verification error: {str(e)}"

                            # In RAW MODE, show ALL matches
                            # In STRICT MODE, only show valid matches
                            if self.raw_mode or is_valid:
                                findings.append({
                                    'type': cat,
                                    'pattern': p_name,
                                    'url': url,
                                    'match': match_str,
                                    'verification': verification_status,
                                    'resource_category': resource_category,
                                    'resource_priority': resource['priority']
                                })
                    except re.error as e:
                        continue  # Skip invalid regex patterns

        if not findings:
            skip_reason = f"No findings for {url}"

        return findings, skip_reason

    def local_scan(self, file_paths, pattern_category, log_callback, finding_callback):
        self.total_urls = len(file_paths)
        results = {

            'total_urls': self.total_urls,

            'findings_count': 0,

            'pattern_breakdown': {},

            'duration': 0,

            'avg_response_time': 0,

            'resource_stats': {category: 0 for category in RESOURCE_CATEGORIES.keys()}
        }

        start_time = time.time()

        # Reset stats for local scan
        self.resource_stats = {category: 0 for category in RESOURCE_CATEGORIES.keys()}
        self.findings_count = 0
        self.regex_match_count = 0

        for file_path in file_paths:

            file_path = file_path.strip()

            if not file_path:

                continue

            try:

                with open(file_path, 'r', encoding='utf-8') as f:

                    content = f.read()

                # Get all findings for the category
                findings_tuple = self.analyze_response(content, file_path, "ALL", pattern_category)

                # analyze_response returns (findings, skip_reason)
                if isinstance(findings_tuple, tuple) and len(findings_tuple) == 2:
                    findings, skip_reason = findings_tuple
                    # Log skip reasons only if they are not "No findings" to avoid cluttering
                    if skip_reason and "No findings" not in skip_reason and log_callback:
                        log_callback(skip_reason)
                else:
                    findings = findings_tuple if findings_tuple is not None else []

                for finding in findings:

                    finding_callback(finding['type'], finding['pattern'], finding['url'], finding['match'], finding.get('verification', 'Format valid'))

                    results['findings_count'] += 1
                    self.findings_count += 1

                    pattern_type = finding['type']

                    if pattern_type not in results['pattern_breakdown']:

                        results['pattern_breakdown'][pattern_type] = 0

                    results['pattern_breakdown'][pattern_type] += 1

            except Exception as e:

                log_callback(f"Error scanning file {file_path}: {str(e)}")

        results['duration'] = time.time() - start_time

        # Add resource statistics to results
        results['resource_stats'] = self.resource_stats

        return results

    def crawl_domain(self, domain, max_pages=100):
        """Crawl the domain to find additional URLs for scanning"""
        visited = set()
        to_visit = [f"https://{domain}", f"http://{domain}"]
        found_urls = []

        while to_visit and len(found_urls) < max_pages and not self.stop_event.is_set():
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue

            visited.add(current_url)

            try:
                if self.proxies:
                    proxy = random.choice(self.proxies)
                    self.session.proxies = {'http': proxy, 'https': proxy}
                self.session.headers['User-Agent'] = self.ua.random
                time.sleep(random.uniform(self.delay, self.delay + 8))
                response = self.session.get(current_url, timeout=5)
                if response.status_code == 200:
                    found_urls.append(current_url)

                    # Extract links from the page
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        absolute_url = urljoin(current_url, href)
                        parsed = urlparse(absolute_url)

                        if parsed.netloc == domain and absolute_url not in visited:
                            to_visit.append(absolute_url)

            except:
                continue

        return found_urls

    def test_proxy(self, proxy):
        """Test if a proxy is working"""
        try:
            proxies = {
                'http': proxy,
                'https': proxy
            }
            response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5)
            return response.status_code == 200
        except:
            return False