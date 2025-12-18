import asyncio
import requests
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.robotparser import RobotFileParser
import dns.resolver
import json
import logging
import getpass
import time
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import argparse
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Manager, Queue
import queue
import os
import sys
from logging.handlers import QueueHandler
from cachetools import TTLCache
from tenacity import retry, stop_after_attempt, wait_exponential
from tqdm import tqdm
from rich.console import Console
from rich.theme import Theme
import re
from lxml import etree

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Initialize rich console for CLI
custom_theme = Theme({"info": "cyan", "warning": "yellow", "error": "red bold"})
console = Console(theme=custom_theme)

# Caches for DNS and robots.txt
dns_cache = TTLCache(maxsize=1000, ttl=3600)
robots_cache = TTLCache(maxsize=1000, ttl=3600)

def create_session():
    """Create a requests session with retries."""
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504, 530])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def get_user_agent():
    """Return a random User-Agent to mimic different browsers."""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    ]
    return random.choice(user_agents)

async def is_valid_url(url, respect_robots=True, timeout=3, logger=None):
    """Check if the URL is valid and accessible using aiohttp."""
    if logger is None:
        logger = logging.getLogger(__name__)
    headers = {"User-Agent": get_user_agent()}
    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            async with session.get(url, timeout=timeout, allow_redirects=True) as response:
                content_type = response.headers.get('content-type', '').lower()
                if response.status == 429:
                    logger.warning(f"Rate limit hit for {url}")
                    return False
                logger.debug(f"URL {url} status {response.status}, content-type: {content_type}")
                if respect_robots and response.status in [200, 301, 302, 403, 404]:
                    if not await is_allowed_by_robots(url, session, headers["User-Agent"], timeout, logger):
                        return False
                return True
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"Failed to validate URL {url}: {e}")
            return False

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def resolve_domain(domain, logger=None):
    """Check if domain resolves via DNS with caching."""
    if logger is None:
        logger = logging.getLogger(__name__)
    if domain in dns_cache:
        return dns_cache[domain]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    try:
        resolver.resolve(domain, 'A')
        dns_cache[domain] = True
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        dns_cache[domain] = False
        return False
    except Exception as e:
        logger.error(f"Error resolving {domain}: {e}")
        dns_cache[domain] = False
        return False

def get_root_domain(url):
    """Extract the root domain (e.g., example.com) from a URL."""
    parsed = urlparse(url)
    domain_parts = parsed.netloc.split('.')
    if len(domain_parts) > 2:
        return '.'.join(domain_parts[-2:])
    return parsed.netloc

async def is_allowed_by_robots(url, session, user_agent, timeout, logger=None):
    """Check if URL is allowed by robots.txt with caching."""
    if logger is None:
        logger = logging.getLogger(__name__)
    parsed = urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    cache_key = f"{robots_url}:{user_agent}"
    if cache_key in robots_cache:
        return robots_cache[cache_key]
    rp = RobotFileParser()
    try:
        async with session.get(robots_url, timeout=timeout) as response:
            rp.parse((await response.text()).splitlines())
            allowed = rp.can_fetch(user_agent, url)
            if not allowed:
                logger.debug(f"URL {url} disallowed by robots.txt")
            robots_cache[cache_key] = allowed
            return allowed
    except Exception as e:
        logger.error(f"Error reading robots.txt for {url}: {e}")
        robots_cache[cache_key] = True
        return True

def clean_url(url):
    """Remove fragments and query strings from URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')

def get_cloudflare_dns_records(tld, api_token, logger=None):
    """Retrieve all DNS records from Cloudflare API."""
    if logger is None:
        logger = logging.getLogger(__name__)
    if not api_token:
        logger.info("No Cloudflare API token provided, skipping Cloudflare DNS lookup")
        return []

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    zone_id = None
    dns_records = []

    try:
        response = requests.get(
            f"https://api.cloudflare.com/client/v4/zones?name={tld}",
            headers=headers,
            timeout=3
        )
        result = response.json()
        if result["success"] and result["result"]:
            zone_id = result["result"][0]["id"]
            logger.info(f"Found Cloudflare zone ID for {tld}: {zone_id}")
        else:
            logger.warning(f"Failed to find zone ID for {tld}: {result}")
            return []
    except Exception as e:
        logger.error(f"Error fetching zone ID for {tld}: {e}")
        return []

    try:
        response = requests.get(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            headers=headers,
            timeout=3
        )
        result = response.json()
        if result["success"]:
            dns_records = result["result"]
            logger.info(f"Retrieved {len(dns_records)} DNS records from Cloudflare")
        else:
            logger.error(f"Failed to retrieve DNS records: {result}")
    except Exception as e:
        logger.error(f"Error fetching DNS records: {e}")

    return dns_records

def get_securitytrails_subdomains(tld, api_key, logger=None):
    """Fetch subdomains from SecurityTrails API."""
    if logger is None:
        logger = logging.getLogger(__name__)
    if not api_key:
        logger.info("No SecurityTrails API key provided, skipping")
        return []
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    try:
        response = requests.get(
            f"https://api.securitytrails.com/v1/domain/{tld}/subdomains",
            headers=headers,
            timeout=3
        )
        result = response.json()
        subdomains = [f"{sub}.{tld}" for sub in result.get("subdomains", [])]
        logger.info(f"Retrieved {len(subdomains)} subdomains from SecurityTrails")
        return subdomains
    except Exception as e:
        logger.error(f"Error fetching SecurityTrails subdomains: {e}")
        return []

def read_wordlist(wordlist_path, logger=None):
    """Read and parse a wordlist file, supporting weights."""
    if logger is None:
        logger = logging.getLogger(__name__)
    subdomains = []
    try:
        if not os.path.exists(wordlist_path):
            logger.error(f"Wordlist file not found: {wordlist_path}")
            return []
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Support format: subdomain:weight or just subdomain
                if ':' in line:
                    subdomain, weight = line.split(':', 1)
                    try:
                        weight = float(weight)
                    except ValueError:
                        logger.warning(f"Invalid weight for {subdomain}, defaulting to 1.0")
                        weight = 1.0
                else:
                    subdomain, weight = line, 1.0
                # Sanitize subdomain
                if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]$', subdomain):
                    subdomains.append((subdomain, weight))
                else:
                    logger.warning(f"Invalid subdomain format: {subdomain}")
        logger.info(f"Loaded {len(subdomains)} subdomains from {wordlist_path}")
        return subdomains
    except Exception as e:
        logger.error(f"Error reading wordlist {wordlist_path}: {e}")
        return []

async def check_subdomain(args):
    """Helper function to check a single subdomain (for multithreading)."""
    subdomain, domain, respect_robots, timeout, progress, progress_lock, include_subdomains, exclude_subdomains, rate_limit_value, rate_limit_lock, logger = args
    try:
        if subdomain:
            full_domain = f"{subdomain}.{domain}"
        else:
            full_domain = domain
        if exclude_subdomains and full_domain in exclude_subdomains:
            logger.debug(f"Skipping excluded subdomain: {full_domain}")
            return None
        if include_subdomains and full_domain not in include_subdomains:
            logger.debug(f"Skipping non-included subdomain: {full_domain}")
            return None
        logger.debug(f"Checking subdomain: {full_domain}")
        if resolve_domain(full_domain, logger):
            url = f"https://{full_domain}"
            with rate_limit_lock:
                current_rate = rate_limit_value['value']
            await asyncio.sleep(random.uniform(current_rate, current_rate * 1.5))
            if await is_valid_url(url, respect_robots, timeout, logger):
                logger.info(f"Found subdomain: {url}")
                if progress is not None:
                    with progress_lock:
                        progress['subdomains_found'] += 1
                with rate_limit_lock:
                    if rate_limit_value['value'] > 0.1:
                        rate_limit_value['value'] = max(0.1, rate_limit_value['value'] * 0.95)
                return url
            elif not await is_valid_url(url, respect_robots, timeout, logger):
                with rate_limit_lock:
                    rate_limit_value['value'] = min(2.0, rate_limit_value['value'] * 1.2)
        return None
    except Exception as e:
        logger.error(f"Error checking subdomain {subdomain}.{domain}: {e}")
        return None

def discover_subdomains(tld, api_token, securitytrails_api_key, session, respect_robots=True, timeout=3, log_queue=None, progress=None, progress_lock=None, include_subdomains=None, exclude_subdomains=None, max_workers=16, rate_limit=0.5, wordlist_path=None):
    """Discover subdomains via Cloudflare DNS, wordlist, SecurityTrails, and crt.sh with multithreading."""
    logger = logging.getLogger(__name__)
    if log_queue is not None:
        logger.handlers = []
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(queue_handler)
        logger.setLevel(logging.INFO)
    
    console.print(f"[info]Starting subdomain discovery for {tld} with {max_workers} workers[/info]")
    subdomains = set()
    include_subdomains = set(include_subdomains or [])
    exclude_subdomains = set(exclude_subdomains or [])
    rate_limit_value = Manager().dict({'value': rate_limit})
    rate_limit_lock = Manager().Lock()

    # Use default wordlist if none provided
    if not wordlist_path:
        wordlist_path = os.path.join(os.path.dirname(__file__), 'subdomains.txt')
        console.print(f"[info]No custom wordlist provided, using default: {wordlist_path}[/info]")

    # Load wordlist
    all_subdomains = read_wordlist(wordlist_path, logger)
    if not all_subdomains:
        console.print(f"[warning]No valid subdomains in wordlist, proceeding with other sources[/warning]")

    # Sort by weight (descending)
    all_subdomains.sort(key=lambda x: x[1], reverse=True)
    subdomains_list = [sub for sub, _ in all_subdomains]

    # Set total subdomains for estimation
    if progress is not None:
        with progress_lock:
            progress['total_subdomains'] = len(subdomains_list) + 50

    async def run_async_checks(args_list):
        tasks = [check_subdomain(args) for args in args_list]
        return await asyncio.gather(*tasks, return_exceptions=True)

    try:
        # 1. Cloudflare DNS records
        console.print("[info]Fetching DNS records from Cloudflare[/info]")
        dns_records = get_cloudflare_dns_records(tld, api_token, logger)
        for record in tqdm(dns_records, desc="Checking Cloudflare DNS", unit="record"):
            name = record["name"]
            if name.endswith(tld) and not name.startswith(('_', '*')):
                subdomain = f"https://{name}"
                if exclude_subdomains and name in exclude_subdomains:
                    continue
                if include_subdomains and name not in include_subdomains:
                    continue
                if resolve_domain(name, logger):
                    with rate_limit_lock:
                        current_rate = rate_limit_value['value']
                    time.sleep(random.uniform(current_rate, current_rate * 1.5))
                    if asyncio.run(is_valid_url(subdomain, respect_robots, timeout, logger)):
                        subdomains.add(subdomain)
                        console.print(f"[info]Found subdomain from Cloudflare DNS: {subdomain}[/info]")
                        if progress is not None:
                            with progress_lock:
                                progress['subdomains_found'] += 1
                        with rate_limit_lock:
                            if rate_limit_value['value'] > 0.1:
                                rate_limit_value['value'] = max(0.1, rate_limit_value['value'] * 0.95)
                    if progress is not None:
                        with progress_lock:
                            progress['status'] = f'Checking Cloudflare DNS: {name}'
    except Exception as e:
        console.print(f"[error]Error in Cloudflare DNS discovery: {e}[/error]")

    try:
        # 2. SecurityTrails API
        console.print("[info]Fetching subdomains from SecurityTrails[/info]")
        securitytrails_domains = get_securitytrails_subdomains(tld, securitytrails_api_key, logger)
        args = [
            (subdomain.split('.')[0], tld, respect_robots, timeout, progress, progress_lock, include_subdomains, exclude_subdomains, rate_limit_value, rate_limit_lock, logger)
            for subdomain in securitytrails_domains
        ]
        results = asyncio.run(run_async_checks(args))
        for i, result in enumerate(tqdm(results, desc="Checking SecurityTrails", unit="subdomain")):
            if result:
                subdomains.add(result)
            if progress is not None and (i % 10 == 0 or i == len(args) - 1):
                with progress_lock:
                    progress['status'] = f'Checking SecurityTrails subdomain {i+1}/{len(args)}'
    except Exception as e:
        console.print(f"[error]Error in SecurityTrails discovery: {e}[/error]")

    try:
        # 3. Brute-force with wordlist (async)
        console.print(f"[info]Brute-forcing subdomains with wordlist using {max_workers} threads[/info]")
        args = [
            (subdomain, tld, respect_robots, timeout, progress, progress_lock, include_subdomains, exclude_subdomains, rate_limit_value, rate_limit_lock, logger)
            for subdomain in subdomains_list
        ]
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.submit(asyncio.run, run_async_checks(args)).result()
            for i, result in enumerate(tqdm(results, desc="Checking wordlist", unit="subdomain")):
                if result:
                    subdomains.add(result)
                if progress is not None and (i % 10 == 0 or i == len(args) - 1):
                    with progress_lock:
                        progress['status'] = f'Checking wordlist subdomain {i+1}/{len(subdomains_list)}'
    except Exception as e:
        console.print(f"[error]Error in wordlist brute-forcing: {e}[/error]")

    try:
        # 4. Certificate transparency logs via crt.sh
        console.print("[info]Fetching subdomains from crt.sh[/info]")
        response = requests.get(f"https://crt.sh/?q=%.{tld}&output=json", timeout=timeout)
        if response.status_code == 200:
            certs = json.loads(response.text)
            args = [
                (name.split('.')[0], tld, respect_robots, timeout, progress, progress_lock, include_subdomains, exclude_subdomains, rate_limit_value, rate_limit_lock, logger)
                for cert in certs
                for name in [cert["name_value"].strip()]
                if '\n' not in name and '%' not in name and not name.startswith("*") and name.endswith(tld)
            ]
            results = asyncio.run(run_async_checks(args))
            for i, result in enumerate(tqdm(results, desc="Checking crt.sh", unit="subdomain")):
                if result:
                    subdomains.add(result)
                if progress is not None and (i % 10 == 0 or i == len(args) - 1):
                    with progress_lock:
                        progress['status'] = f'Checking crt.sh subdomain {i+1}/{len(args)}'
    except Exception as e:
        console.print(f"[error]Error fetching from crt.sh: {e}[/error]")

    console.print(f"[info]Discovered {len(subdomains)} subdomains for {tld}[/info]")
    return subdomains

async def crawl_url(args):
    """Crawl a single URL and return found links, respecting max depth (for multithreading)."""
    url, visited, collected_urls, collected_urls_lock, root_domain, respect_robots, timeout, progress, progress_lock, max_depth, current_depth, rate_limit_value, rate_limit_lock, log_queue = args
    logger = logging.getLogger(__name__)
    if log_queue is not None:
        logger.handlers = []
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(queue_handler)
        logger.setLevel(logging.INFO)
    
    async with aiohttp.ClientSession(headers={"User-Agent": get_user_agent()}) as session:
        try:
            if url in visited or current_depth > max_depth:
                logger.debug(f"Skipping URL {url}: already visited or depth {current_depth} > {max_depth}")
                return []

            visited.append(url)
            logger.info(f"Crawling (depth {current_depth}): {url}")
            with rate_limit_lock:
                current_rate = rate_limit_value['value']
            await asyncio.sleep(random.uniform(current_rate, current_rate * 1.5))
            async with session.get(url, timeout=timeout) as response:
    content_type = response.headers.get('content-type', '').lower()

    if response.status == 429:
        with rate_limit_lock:
            rate_limit_value['value'] = min(2.0, rate_limit_value['value'] * 1.2)
        logger.warning(f"Rate limit hit for {url}")
        return []

    if response.status not in (200, 301, 302):
        return []

    if "text/html" not in content_type:
        return []

    with rate_limit_lock:
        rate_limit_value['value'] = max(0.1, rate_limit_value['value'] * 0.95)

    raw = await response.read()
    text = raw.decode(response.charset or "utf-8", errors="ignore")

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"Failed to crawl {url}: {e}")
            return []

        with collected_urls_lock:
            collected_urls['urls'].append(clean_url(url))
        if progress is not None:
            with progress_lock:
                progress['urls_crawled'] += 1
        found_urls = []
        if 'text/html' in content_type:
            soup = BeautifulSoup(text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(url, href)

                if not absolute_url.startswith(('http://', 'https://')):
                    continue

                parsed_url = urlparse(absolute_url)
                if not parsed_url.netloc.endswith(root_domain):
                    continue

                cleaned_url = clean_url(absolute_url)
                if await is_valid_url(cleaned_url, respect_robots, timeout, logger) and cleaned_url not in visited:
                    found_urls.append((cleaned_url, current_depth + 1))

        return found_urls

def crawl_website(start_urls, root_domain, respect_robots=True, timeout=3, log_queue=None, progress=None, progress_lock=None, use_multithreading=False, max_workers=16, max_depth=5, rate_limit=0.5):
    """Crawl the website and subdomains, using multithreading and async I/O."""
    logger = logging.getLogger(__name__)
    if log_queue is not None:
        logger.handlers = []
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(queue_handler)
        logger.setLevel(logging.INFO)
    
    console.print(f"[info]Starting crawl for {root_domain} with {len(start_urls)} start URLs[/info]")
    rate_limit_value = Manager().dict({'value': rate_limit})
    rate_limit_lock = Manager().Lock()
    visited = Manager().list()
    collected_urls = {'urls': Manager().list(), 'lock': Manager().Lock()}

    async def run_async_crawl(args_list):
        tasks = [crawl_url(args) for args in args_list]
        return await asyncio.gather(*tasks, return_exceptions=True)

    try:
        if not use_multithreading:
            console.print("[info]Crawling website (single thread)[/info]")
            for start_url in tqdm(start_urls, desc="Crawling URLs", unit="url"):
                url_queue = [(start_url, 0)]
                while url_queue:
                    url, depth = url_queue.pop(0)
                    args = (url, visited, collected_urls, collected_urls['lock'], root_domain, respect_robots, timeout, progress, progress_lock, max_depth, depth, rate_limit_value, rate_limit_lock, log_queue)
                    new_urls = asyncio.run(crawl_url(args))
                    url_queue.extend((u, d) for u, d in new_urls if u not in visited)
        else:
            console.print(f"[info]Crawling website using {max_workers} threads[/info]")
            url_queue = queue.Queue()
            for start_url in start_urls:
                url_queue.put((start_url, 0))

            def worker():
                logger = logging.getLogger(__name__)
                if log_queue is not None:
                    logger.handlers = []
                    queue_handler = QueueHandler(log_queue)
                    queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                    logger.addHandler(queue_handler)
                    logger.setLevel(logging.INFO)
                while True:
                    try:
                        url, depth = url_queue.get_nowait()
                    except queue.Empty:
                        break
                    args = (url, visited, collected_urls, collected_urls['lock'], root_domain, respect_robots, timeout, progress, progress_lock, max_depth, depth, rate_limit_value, rate_limit_lock, log_queue)
                    new_urls = asyncio.run(crawl_url(args))
                    for new_url, new_depth in new_urls:
                        if new_url not in visited:
                            url_queue.put((new_url, new_depth))
                    url_queue.task_done()

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(worker) for _ in range(max_workers)]
                for future in futures:
                    future.result()

        console.print(f"[info]Crawled {len(collected_urls['urls'])} URLs[/info]")
        return set(collected_urls['urls'])
    except Exception as e:
        console.print(f"[error]Error in crawl_website: {e}[/error]")
        return set()

def validate_sitemap(output_file, logger=None):
    """Validate sitemap.xml against Sitemap Protocol schema."""
    if logger is None:
        logger = logging.getLogger(__name__)
    schema_url = "http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd"
    try:
        schema_response = requests.get(schema_url, timeout=5)
        schema_doc = etree.fromstring(schema_response.content)
        schema = etree.XMLSchema(schema_doc)
        parser = etree.XMLParser(schema=schema)
        with open(output_file, 'rb') as f:
            etree.parse(f, parser)
        logger.info(f"Sitemap {output_file} is valid against Sitemap Protocol")
        return True
    except Exception as e:
        logger.error(f"Sitemap validation failed for {output_file}: {e}")
        return False

def generate_sitemap(urls, output_file="sitemap.xml", log_queue=None):
    """Generate and validate sitemap.xml from a set of URLs."""
    logger = logging.getLogger(__name__)
    if log_queue is not None:
        logger.handlers = []
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(queue_handler)
        logger.setLevel(logging.INFO)
    
    try:
        urlset = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")

        for url in sorted(urls):
            url_element = ET.SubElement(urlset, "url")
            loc = ET.SubElement(url_element, "loc")
            loc.text = url
            lastmod = ET.SubElement(url_element, "lastmod")
            lastmod.text = datetime.now().strftime("%Y-%m-%d")
            changefreq = ET.SubElement(url_element, "changefreq")
            changefreq.text = "weekly"
            priority = ET.SubElement(url_element, "priority")
            priority.text = "0.8"

        tree = ET.ElementTree(urlset)
        ET.indent(tree, space="  ", level=0)
        tree.write(output_file, encoding="utf-8", xml_declaration=True)
        logger.info(f"Sitemap generated: {output_file}")
        validate_sitemap(output_file, logger)
    except Exception as e:
        logger.error(f"Error generating sitemap: {e}")

def run_sitemap_generation(tld, api_token, securitytrails_api_key, respect_robots=True, timeout=3, log_queue=None, progress=None, progress_lock=None, use_multithreading=False, max_workers=16, max_depth=5, output_file="sitemap.xml", include_subdomains=None, exclude_subdomains=None, rate_limit=0.5, wordlist_path=None):
    """Run the sitemap generation process."""
    logger = logging.getLogger(__name__)
    if log_queue is not None:
        logger.handlers = []
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(queue_handler)
        logger.setLevel(logging.INFO)

    try:
        if not tld or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}$', tld):
            logger.error("Invalid or no domain provided. Exiting.")
            if progress and progress_lock:
                with progress_lock:
                    progress['status'] = 'error'
                    progress['error_message'] = 'Invalid or no domain provided'
                    progress['is_generating'] = False
            return

        console.print(f"[info]Starting sitemap generation for {tld} with timeout: {timeout}s, multithreading: {use_multithreading}, max_workers: {max_workers}, max_depth: {max_depth}, output: {output_file}[/info]")

        # Discover subdomains
        console.print(f"[info]Discovering subdomains for {tld}[/info]")
        session = create_session()
        start_urls = discover_subdomains(tld, api_token, securitytrails_api_key, session, respect_robots, timeout, log_queue, progress, progress_lock, include_subdomains, exclude_subdomains, max_workers, rate_limit, wordlist_path)
        if not start_urls:
            console.print(f"[error]No accessible subdomains found for {tld}. Exiting.[/error]")
            if progress and progress_lock:
                with progress_lock:
                    progress['status'] = 'error'
                    progress['error_message'] = 'No accessible subdomains found'
                    progress['is_generating'] = False
            return

        root_domain = tld
        console.print(f"[info]Crawling {tld} including all subdomains[/info]")
        urls = crawl_website(start_urls, root_domain, respect_robots, timeout, log_queue, progress, progress_lock, use_multithreading, max_workers, max_depth, rate_limit)
        if not urls:
            console.print("[warning]No URLs were crawled. Sitemap may be empty.[/warning]")
            if progress and progress_lock:
                with progress_lock:
                    progress['status'] = 'error'
                    progress['error_message'] = 'No URLs were crawled'
                    progress['is_generating'] = False
        else:
            generate_sitemap(urls, output_file, log_queue)
            console.print(f"[info]Found {len(urls)} unique pages across main domain and subdomains.[/info]")
            if progress and progress_lock:
                with progress_lock:
                    progress['status'] = 'completed'
                    progress['is_generating'] = False
    except Exception as e:
        console.print(f"[error]Error in sitemap generation: {e}[/error]")
        if progress and progress_lock:
            with progress_lock:
                progress['status'] = 'error'
                progress['error_message'] = f'Sitemap generation failed: {str(e)}'
                progress['is_generating'] = False

def main_cli(args):
    """Run the sitemap generator in CLI mode."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logger = logging.getLogger(__name__)
    file_handler = logging.FileHandler('sitemap.log')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

    tld = args.tld or input("Enter the top-level domain (e.g., example.com): ").strip()
    api_token = args.api_token or getpass.getpass(
        "Enter your Cloudflare API token (leave blank to skip): "
    ).strip()
    securitytrails_api_key = args.securitytrails_api_key or getpass.getpass(
        "Enter your SecurityTrails API key (leave blank to skip): "
    ).strip()
    respect_robots = args.respect_robots
    timeout = args.timeout
    use_multithreading = args.multi
    max_workers = args.cores
    if max_workers == 'auto':
        max_workers = (os.cpu_count() or 4) * 4
    else:
        max_workers = int(max_workers)
    max_depth = args.max_depth
    output_file = args.output
    include_subdomains = args.include_subdomains.split(',') if args.include_subdomains else None
    exclude_subdomains = args.exclude_subdomains.split(',') if args.exclude_subdomains else None
    rate_limit = args.rate_limit
    wordlist_path = args.wordlist

    manager = Manager()
    progress = manager.dict({
        'subdomains_found': 0,
        'urls_crawled': 0,
        'total_subdomains': 0,
        'start_time': time.time(),
        'status': 'running',
        'error_message': '',
        'is_generating': True
    })
    progress_lock = manager.Lock()

    run_sitemap_generation(
        tld, api_token, securitytrails_api_key, respect_robots, timeout, None, progress, progress_lock,
        use_multithreading, max_workers, max_depth, output_file,
        include_subdomains, exclude_subdomains, rate_limit, wordlist_path
    )

def main():
    """Main entry point with CLI/WebUI mode selection."""
    parser = argparse.ArgumentParser(description="Sitemap Generator for Cloudflare-hosted domains")
    parser.add_argument("--webui", action="store_true", help="Run in WebUI mode")
    parser.add_argument("--tld", type=str, help="Top-level domain (e.g., example.com)")
    parser.add_argument("--api-token", type=str, help="Cloudflare API token")
    parser.add_argument("--securitytrails-api-key", type=str, help="SecurityTrails API key")
    parser.add_argument("--no-robots", action="store_false", dest="respect_robots", help="Ignore robots.txt")
    parser.add_argument("--timeout", type=float, default=5, help="Timeout in seconds")
    parser.add_argument("--multi", action="store_true", help="Enable multithreading")
    parser.add_argument("-c", "--cores", default=4, help="Number of threads for multithreading (or 'auto')")
    parser.add_argument("--max-depth", type=int, default=5, help="Maximum crawl depth")
    parser.add_argument("--output", type=str, default="sitemap.xml", help="Output sitemap file name")
    parser.add_argument("--include-subdomains", type=str, help="Comma-separated list of subdomains to include")
    parser.add_argument("--exclude-subdomains", type=str, help="Comma-separated list of subdomains to exclude")
    parser.add_argument("--rate-limit", type=float, default=0.5, help="Initial delay between requests in seconds")
    parser.add_argument("--wordlist", type=str, help="Path to custom wordlist file")
    args = parser.parse_args()

    if args.webui:
        try:
            if not os.path.exists(os.path.join(os.path.dirname(__file__), 'app.py')):
                console.print("[error]WebUI module not found. Please ensure app.py is available.[/error]")
                return
            from app import run_webui
            customize_port = input("Customize port? (y/n, default: n): ").strip().lower()
            port = 5000
            if customize_port == 'y':
                while True:
                    port_input = input("Enter port number: ").strip()
                    try:
                        port = int(port_input)
                        if not (1 <= port <= 65535):
                            raise ValueError("Port must be between 1 and 65535")
                        break
                    except ValueError as e:
                        console.print(f"[error]Invalid port: {e}. Please enter a valid number.[/error]")
            run_webui(port=port)
        except ImportError as e:
            console.print(f"[error]Failed to import WebUI module: {e}. Please ensure app.py is available and dependencies are installed.[/error]")
            return
        except Exception as e:
            console.print(f"[error]Error starting WebUI: {e}[/error]")
            return
    else:
        main_cli(args)

if __name__ == "__main__":
    main()
