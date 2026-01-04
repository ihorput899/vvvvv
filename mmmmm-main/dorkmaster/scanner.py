# scanner.py - Core scanning engine for DorkStrike PRO

import asyncio
import aiohttp
import requests
import re
import time
import threading
import random
import os
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from patterns import DorkPatterns, calculate_shannon_entropy
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
    def __init__(
        self,
        proxies=None,
        search_engines=None,
        sources=None,
        use_js_rendering=False,
        verify_api_keys=False,
        strictness="medium",
        depth=3,
        custom_dorks=None,
        raw_mode=False,
        delay=5.0,
        proxy_type="SOCKS5",
        ua_rotate=True,
        ui_callback=None,
    ):
        self.patterns = DorkPatterns()
        self.stop_event = threading.Event()
        self.session = requests.Session()
        self.proxies = proxies or []
        self.ua = UserAgent()
        self.search_engines = search_engines or ['google']  # Default to Google

        if sources is None:
            inferred_sources = []
            for engine in self.search_engines:
                if engine.lower() in {"wayback", "github"}:
                    inferred_sources.append(engine.lower())
            self.sources = inferred_sources or ["wayback"]
        else:
            self.sources = [s.lower() for s in sources if s]

        self.use_js_rendering = use_js_rendering and PLAYWRIGHT_AVAILABLE
        self.verify_api_keys = verify_api_keys
        self.strictness = strictness.lower()
        self.depth = depth
        self.request_count = 0
        self.custom_dorks = custom_dorks or []
        self.raw_mode = raw_mode
        self.delay = delay
        self.proxy_type = proxy_type
        self.ua_rotate = ua_rotate
        self.ui_callback = ui_callback
        
        # Resource classification tracking
        self.resource_stats = {category: 0 for category in RESOURCE_CATEGORIES.keys()}
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

    async def scan_async(self, target_domain, pattern_category, max_concurrent, progress_callback, log_callback):
        """Async version of scan method overhauled for Wayback Pipeline"""
        start_time = time.time()
        self.target_domain = target_domain

        log_callback("="*60)
        log_callback(f"SCAN STARTED: {target_domain}")
        log_callback(f"Pattern Category: {pattern_category}")
        log_callback(f"Raw Mode: {'ENABLED' if self.raw_mode else 'DISABLED'}")
        log_callback(f"Verify API Keys: {'ENABLED' if self.verify_api_keys else 'DISABLED'}")
        log_callback("="*60)

        # Reset per-scan counters
        self.download_success_count = 0
        self.regex_match_count = 0
        self.findings_count = 0

        self.wayback_total_urls = 0
        self.github_total_urls = 0

        enabled_sources = {s.lower() for s in (self.sources or [])}
        if not enabled_sources:
            enabled_sources = {"wayback"}

        url_data_by_source = {}

        # 1) WAYBACK
        if "wayback" in enabled_sources:
            log_callback(f"\n[WAYBACK] SEARCH: Querying Wayback Machine for {target_domain}...")
            wayback_urls = await self.fetch_from_wayback(target_domain, log_callback)
            self.wayback_total_urls = len(wayback_urls)
            url_data_by_source["WAYBACK"] = [(u, "ALL", pattern_category, "WAYBACK") for u in wayback_urls]
            log_callback(f"[WAYBACK] SEARCH COMPLETE: Found {self.wayback_total_urls} archived URLs")

        # 2) GITHUB
        if "github" in enabled_sources:
            log_callback(f"\n[GITHUB] SEARCH: Querying GitHub for {target_domain}...")
            github_items = await self.fetch_from_github(target_domain, log_callback)
            self.github_total_urls = len(github_items)
            url_data_by_source["GITHUB"] = [(item.get("url"), "ALL", pattern_category, "GITHUB", item) for item in github_items]
            log_callback(f"[GITHUB] SEARCH COMPLETE: Found {self.github_total_urls} candidate files")

        # 3) CUSTOM DIRECT URLS (optional)
        custom_urls = []
        for dork in self.custom_dorks:
            if dork.startswith("http"):
                url = dork.replace("{target}", target_domain)
                custom_urls.append(url)

        if custom_urls:
            log_callback(f"\n[CUSTOM] Adding {len(custom_urls)} custom URLs")
            url_data_by_source["CUSTOM"] = [(u, "ALL", pattern_category, "CUSTOM") for u in custom_urls]

        # Flatten and de-duplicate by URL
        seen_urls = set()
        url_data_list = []
        for source_name, source_items in url_data_by_source.items():
            for url_data in source_items:
                url = url_data[0] if isinstance(url_data, tuple) else None
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                url_data_list.append(url_data)

        self.total_urls = len(url_data_list)
        total_urls = self.total_urls

        log_callback(f"\n[STAGE 1] COMPLETE: Total URLs/files queued: {total_urls}")

        results = {
            'total_urls': total_urls,
            'findings_count': 0,
            'pattern_breakdown': {},
            'duration': 0,
            'avg_response_time': 0,
            'download_success': 0,
            'regex_matches': 0
        }

        findings = []
        response_times = []

        # STAGE 2: FETCH AND MATCH
        log_callback(f"\n[STAGE 2] FETCH & MATCH: Downloading content and analyzing patterns...")
        log_callback(f"Concurrent threads: {max_concurrent}")

        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(max_concurrent)

        # Create aiohttp session with connector settings
        connector = aiohttp.TCPConnector(limit=max_concurrent)
        timeout = aiohttp.ClientTimeout(total=20, connect=10)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            _, findings, response_times = await self._process_urls(
                session=session,
                url_data_list=url_data_list,
                pattern_category=pattern_category,
                semaphore=semaphore,
                max_concurrent=max_concurrent,
                progress_callback=progress_callback,
                log_callback=log_callback,
                results=results,
                total_urls=total_urls,
            )

        results['duration'] = time.time() - start_time
        if response_times:
            results['avg_response_time'] = sum(response_times) / len(response_times)

        # Update results with pipeline stats
        results['download_success'] = self.download_success_count
        results['regex_matches'] = self.regex_match_count

        # Log summary stages
        log_callback(f"\n[STAGE 2] CONTENT FETCH: {self.download_success_count} downloads attempted")
        log_callback(f"[STAGE 3] PATTERN MATCH: {self.regex_match_count} regex matches found")
        log_callback(f"[STAGE 4] FINAL RESULTS: {results['findings_count']} findings reported")

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

    async def _process_urls(
        self,
        session,
        url_data_list,
        pattern_category,
        semaphore,
        max_concurrent,
        progress_callback,
        log_callback,
        results,
        total_urls,
    ):
        """Process queued URLs/files (any source) with concurrency limits."""

        tasks = []
        completed = 0
        findings = []
        response_times = []

        for url_data in url_data_list:
            if self.stop_event.is_set():
                break

            task = asyncio.create_task(
                self.scan_url_async(session, url_data, pattern_category, semaphore, log_callback)
            )
            tasks.append(task)

            if len(tasks) >= max_concurrent:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                tasks = list(pending)

                completed, findings, response_times = self._consume_scan_tasks(
                    done,
                    completed,
                    total_urls,
                    findings,
                    response_times,
                    results,
                    progress_callback,
                    log_callback,
                )

        if tasks and not self.stop_event.is_set():
            done, _ = await asyncio.wait(tasks)
            completed, findings, response_times = self._consume_scan_tasks(
                done,
                completed,
                total_urls,
                findings,
                response_times,
                results,
                progress_callback,
                log_callback,
            )

        return completed, findings, response_times

    def _consume_scan_tasks(
        self,
        done_tasks,
        completed,
        total_urls,
        findings,
        response_times,
        results,
        progress_callback,
        log_callback,
    ):
        for task in done_tasks:
            if self.stop_event.is_set():
                break
            try:
                url_findings, response_time = task.result()
                response_times.append(response_time)
                findings.extend(url_findings)

                for finding in url_findings:
                    results['findings_count'] += 1
                    self.findings_count += 1

                    pattern_type = finding['type']
                    if pattern_type not in results['pattern_breakdown']:
                        results['pattern_breakdown'][pattern_type] = 0
                    results['pattern_breakdown'][pattern_type] += 1

            except Exception as e:
                if log_callback:
                    log_callback(f"Error processing task: {str(e)}")

            completed += 1
            progress = (completed / total_urls) * 100 if total_urls > 0 else 100
            progress_callback(progress)

        return completed, findings, response_times

    def scan(self, target_domain, pattern_category, max_concurrent, progress_callback, log_callback):
        """Main scan method - now uses asyncio internally"""
        self.stop_event.clear()

        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            # Run the async scan
            results = loop.run_until_complete(
                self.scan_async(target_domain, pattern_category, max_concurrent, progress_callback, log_callback)
            )
            return results
        finally:
            loop.close()

    def generate_dork_urls(self, target_domain, pattern_category):
        """
        Generate dork URLs for scanning.
        NOTE: This method is deprecated for remote scanning.
        Use fetch_from_wayback() instead for the new pipeline.
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
        The scanner now uses Wayback Machine CDX API via fetch_from_wayback().
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

    def _is_binary(self, url: str) -> bool:
        binary_ext = {
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".webp",
            ".svg",
            ".ico",
            ".mp4",
            ".mov",
            ".mp3",
            ".wav",
            ".exe",
            ".dll",
            ".zip",
            ".tar",
            ".gz",
            ".rar",
            ".7z",
            ".pdf",
            ".woff",
            ".woff2",
            ".ttf",
        }

        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in binary_ext)

    async def fetch_from_wayback(self, target, log_callback=None):
        """Wayback = историческое хранилище домена.

        1) CDX API -> список URL + timestamp
        2) Сбор archived URL: https://web.archive.org/web/{timestamp}/{original}
        """
        found_urls = []

        if log_callback:
            log_callback(f"[WAYBACK] Fetching archived URLs for {target}...")

        url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": target,
            "matchType": "domain",
            "output": "json",
            "collapse": "urlkey",
            "filter": "statuscode:200",
            "limit": 10000,
        }

        timeout = aiohttp.ClientTimeout(total=30, connect=10)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json(content_type=None)
                        for row in data[1:]:
                            if len(row) >= 3:
                                timestamp = row[1]
                                original_url = row[2]
                                if not self._is_binary(original_url):
                                    found_urls.append(
                                        f"https://web.archive.org/web/{timestamp}/{original_url}"
                                    )
                    elif response.status == 429 and log_callback:
                        log_callback("[WAYBACK] Rate limited")
        except Exception as e:
            if log_callback:
                log_callback(f"[WAYBACK] Error: {e}")

        found_urls = list(set(found_urls))
        if log_callback:
            log_callback(f"[WAYBACK] Total unique archived URLs: {len(found_urls)}")

        return found_urls

    def _github_headers(self):
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "DorkStrikePRO",
        }

        token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        return headers

    async def fetch_from_github(self, target, log_callback=None):
        """GitHub = утёкшие репозитории/файлы.

        Используется GitHub Code Search API:
        - https://api.github.com/search/code?q=...
        """
        target = (target or "").strip()
        if not target:
            return []

        target_short = target.split(".")[0]
        target_short = re.sub(r"[^a-zA-Z0-9_-]", "", target_short)

        search_queries = [
            f'"{target}"',
            f'"{target}" filename:.env',
        ]

        if target_short:
            search_queries.extend(
                [
                    f"org:{target_short} filename:.env",
                    f"user:{target_short} filename:.env",
                ]
            )

        api_url = "https://api.github.com/search/code"
        headers = self._github_headers()
        timeout = aiohttp.ClientTimeout(total=20, connect=10)

        results = []
        seen = set()

        try:
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                for query in search_queries:
                    if self.stop_event.is_set():
                        break

                    params = {"q": query, "per_page": 100}

                    try:
                        async with session.get(api_url, params=params) as resp:
                            if resp.status == 200:
                                data = await resp.json(content_type=None)

                                for item in data.get("items", []):
                                    html_url = item.get("html_url")
                                    if not html_url:
                                        continue

                                    raw_url = (
                                        html_url.replace(
                                            "https://github.com/", "https://raw.githubusercontent.com/"
                                        ).replace("/blob/", "/")
                                    )

                                    if self._is_binary(raw_url) or raw_url in seen:
                                        continue

                                    seen.add(raw_url)

                                    repo = item.get("repository", {})
                                    results.append(
                                        {
                                            "url": raw_url,
                                            "repo": repo.get("full_name") or repo.get("html_url"),
                                            "file": item.get("path"),
                                            "source": "github",
                                            "query": query,
                                        }
                                    )

                            elif resp.status in {403, 429}:
                                if log_callback:
                                    log_callback(
                                        f"[GITHUB] Rate limited / forbidden (status {resp.status}). Consider setting GITHUB_TOKEN."
                                    )
                                break
                            elif resp.status == 422 and log_callback:
                                log_callback(f"[GITHUB] Invalid query: {query}")
                    except Exception as e:
                        if log_callback:
                            log_callback(f"[GITHUB] Error for query '{query}': {e}")
        except Exception as e:
            if log_callback:
                log_callback(f"[GITHUB] Error: {e}")

        if log_callback:
            log_callback(f"[GITHUB] Total unique candidate files: {len(results)}")

        return results

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
        """Async version of scan_url"""

        meta = None
        source = "WAYBACK"

        if isinstance(url_data, (list, tuple)):
            if len(url_data) == 3:
                url, pattern_name, category = url_data
            elif len(url_data) == 4:
                url, pattern_name, category, source = url_data
            else:
                url, pattern_name, category, source, meta = url_data[:5]
        else:
            url = str(url_data)
            pattern_name = "ALL"
            category = pattern_category

        start_time = time.time()

        if self.stop_event.is_set():
            return [], 0

        async with semaphore:  # Limit concurrent requests
            try:
                if self.stop_event.is_set():
                    return [], 0

                # Use JS rendering if enabled
                html_content = None
                if self.use_js_rendering:
                    # Run JS rendering in thread pool since Playwright is sync
                    loop = asyncio.get_event_loop()
                    html_content = await loop.run_in_executor(None, self.render_page_with_js, url)
                    if html_content:
                        self.download_success_count += 1
                else:
                    # Use aiohttp for regular requests
                    headers = {'User-Agent': self.get_fresh_user_agent()}
                    # Use timeout as requested
                    timeout = aiohttp.ClientTimeout(total=10, connect=5)

                    try:
                        async with session.get(url, headers=headers, timeout=timeout) as response:
                            # Fetch everything as requested, not just 200
                            html_content = await response.text()
                            self.download_success_count += 1
                    except Exception as e:
                        if log_callback:
                            log_callback(f"Download failed: {str(e)} for {url}")
                        return [], time.time() - start_time

                if self.stop_event.is_set():
                    return [], time.time() - start_time

                if html_content:
                    # Run analysis in thread pool since it's CPU-bound
                    loop = asyncio.get_event_loop()
                    result_tuple = await loop.run_in_executor(
                        None, self.analyze_response, html_content, url, pattern_name, category, source
                    )

                    findings, _ = result_tuple if isinstance(result_tuple, tuple) else (result_tuple, None)

                    if self.stop_event.is_set():
                        return [], time.time() - start_time

                    # Real-time push results
                    for finding in findings:
                        if self.ui_callback:
                            payload = {
                                'url': url,
                                'source': source,
                                'pattern': finding['pattern'],
                                'match': finding['match'],
                                'status': 'RAW',
                                'type': finding['type'],
                            }
                            if isinstance(meta, dict):
                                payload['repo'] = meta.get('repo')
                                payload['file'] = meta.get('file')
                            self.ui_callback(payload)

                    return findings, time.time() - start_time
                else:
                    return [], time.time() - start_time

            except Exception:
                return [], time.time() - start_time

    def scan_url(self, url_data, pattern_category):
        """Scan a single dork URL with optional JS rendering"""

        meta = None
        source = "WAYBACK"

        if isinstance(url_data, (list, tuple)):
            if len(url_data) == 3:
                url, pattern_name, category = url_data
            elif len(url_data) == 4:
                url, pattern_name, category, source = url_data
            else:
                url, pattern_name, category, source, meta = url_data[:5]
        else:
            url = str(url_data)
            pattern_name = "ALL"
            category = pattern_category

        start_time = time.time()

        try:
            html_content = None

            # Try JS rendering first if enabled
            if self.use_js_rendering:
                html_content = self.render_page_with_js(url)
                response_time = time.time() - start_time
                if html_content:
                    self.download_success_count += 1
            else:
                # Fallback to regular requests
                if self.proxies:
                    proxy = random.choice(self.proxies)
                    self.session.proxies = {'http': proxy, 'https': proxy}
                self.session.headers['User-Agent'] = self.ua.random
                time.sleep(random.uniform(self.delay, self.delay + 8))
                response = self.session.get(url, timeout=10)
                response_time = time.time() - start_time
                
                # Fetch everything as requested
                html_content = response.text
                self.download_success_count += 1

            if html_content:
                result_tuple = self.analyze_response(html_content, url, pattern_name, category, source)
                findings, _ = result_tuple if isinstance(result_tuple, tuple) else (result_tuple, None)

                # Real-time push results
                for finding in findings:
                    if self.ui_callback:
                        payload = {
                            'url': url,
                            'source': source,
                            'pattern': finding['pattern'],
                            'match': finding['match'],
                            'status': 'RAW',
                            'type': finding['type'],
                        }
                        if isinstance(meta, dict):
                            payload['repo'] = meta.get('repo')
                            payload['file'] = meta.get('file')
                        self.ui_callback(payload)
                return findings, response_time
            else:
                return [], response_time

        except Exception:
            return [], time.time() - start_time

    def analyze_response(self, html_content, url, pattern_name, category, source="WAYBACK"):
        """
        RAW MODE: никакой логики, только re.findall()
        """
        findings = []

        source = (source or "WAYBACK").upper()

        if category == "ALL":
            categories_to_check = ["CRYPTO", "SECRETS", "VULNERABILITIES"]
        else:
            categories_to_check = [category]

        for cat in categories_to_check:
            patterns = self.patterns.get_patterns(cat)

            for p_name, pattern_data in patterns.items():
                # Filter by pattern_name if specified
                if pattern_name != "ALL" and pattern_name != "CUSTOM" and pattern_name != p_name:
                    continue

                regex_patterns = pattern_data.get('regex', [])

                for regex in regex_patterns:
                    try:
                        matches = re.findall(regex, html_content, re.IGNORECASE | re.MULTILINE)
                        for match in matches:
                            self.regex_match_count += 1

                            # Handle tuple matches from regex groups
                            if isinstance(match, tuple):
                                match_str = str(match[-1])[:100] if match[-1] else str(match[0])[:100]
                            else:
                                match_str = str(match)[:100]

                            findings.append({
                                'type': cat,
                                'pattern': p_name,
                                'url': url,
                                'match': match_str,
                                'verification': 'RAW',
                                'status': 'RAW',
                                'source': source,
                            })
                    except re.error:
                        continue

        return findings, None

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
                findings_tuple = self.analyze_response(content, file_path, "ALL", pattern_category, "LOCAL")

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