#!/usr/bin/env python3
"""
endpoint_checker.py

- Discover endpoints for domains (robots.txt, sitemap.xml, basic crawl)
- Run safe checks: reflected XSS (non-executing reflection), boolean SQLi (response diff),
  open-redirect detection (harmless example.com target).
- Export JSON + HTML report.

Usage:
  python3 endpoint_checker.py -t https://example.com -o report_week07 --concurrency 40 --crawl-depth 2

Safety: Only run against systems you own or are authorized to test.
Author: Produced for Week 07 Task 02 (Developed by Muneeb)
"""

from __future__ import annotations
import argparse
import asyncio
import json
import logging
import random
import re
import sys
import time
from dataclasses import dataclass, asdict
from typing import Optional, List, Set, Dict, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, ParseResult
import os

import aiohttp
from aiohttp import ClientTimeout
from lxml import etree
from bs4 import BeautifulSoup
from jinja2 import Template

# ---------- Configuration ----------
DEFAULT_TIMEOUT = 6
DEFAULT_CONCURRENCY = 50
DEFAULT_CRAWL_DEPTH = 1
USER_AGENT = "EndpointChecker/1.0 (+https://example.com)"
SAFE_REDIRECT_TARGET = "https://example.com/"  # harmless canonical target for open-redirect testing

# ---------- Banner (RECON) ----------
BANNER_RECON = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

             --- RECON | Made by: Muneeb Ahmed ---
"""
def print_banner(target: str) -> None:
    """
    Print a stylized RECON banner to the console. If stdout is a TTY, use ANSI color.
    Call this right before starting analysis for a target.
    """
    is_tty = sys.stdout.isatty()
    header = f"Starting recon for target: {target}\n"
    if is_tty:
        # ANSI colors: bold cyan for banner, yellow for header
        cyan = "\033[96m"
        yellow = "\033[93m"
        bold = "\033[1m"
        reset = "\033[0m"
        print(cyan + bold + BANNER_RECON + reset)
        print(yellow + header + reset)
    else:
        print(BANNER_RECON)
        print(header)

# ---------- Data structures ----------
@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: List[str] = None

@dataclass
class CheckFinding:
    issue: str
    severity: str
    detail: str
    evidence: str

@dataclass
class EndpointResult:
    endpoint: Endpoint
    open_redirect: Optional[CheckFinding] = None
    reflected_xss: Optional[CheckFinding] = None
    sqli: Optional[CheckFinding] = None
    raw_responses: Dict[str, str] = None

# ---------- Helpers ----------
def normalize_target(t: str) -> str:
    t = t.strip()
    if not t:
        raise ValueError("Empty target")
    if not urlparse(t).scheme:
        t = "https://" + t
    return t.rstrip("/")

def random_marker() -> str:
    return "INJ-" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(8))

def is_same_origin(u1: str, u2: str) -> bool:
    p1, p2 = urlparse(u1), urlparse(u2)
    return (p1.scheme, p1.hostname, p1.port) == (p2.scheme, p2.hostname, p2.port)

# ---------- Discovery ----------

async def fetch_text(session: aiohttp.ClientSession, url: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[int, str, Dict]:
    try:
        async with session.get(url, timeout=ClientTimeout(total=timeout), allow_redirects=True) as resp:
            text = await resp.text(errors="ignore")
            return resp.status, text, {"final_url": str(resp.url), "headers": dict(resp.headers)}
    except Exception as e:
        logging.debug("fetch_text fail %s -> %s", url, e)
        return 0, "", {}

async def discover_robots_and_sitemap(session: aiohttp.ClientSession, base: str) -> Set[str]:
    """Return discovered URLs from robots.txt and sitemap.xml if present."""
    found = set()
    robots_url = urljoin(base, "/robots.txt")
    status, text, meta = await fetch_text(session, robots_url)
    if status and text:
        # parse Disallow/Allow and Sitemap lines
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                if sitemap_url:
                    found.update(await parse_sitemap(session, sitemap_url))
            elif line.lower().startswith(("allow:", "disallow:")):
                # we won't use disallow for discovery, but if it contains a path, add domain+path
                parts = line.split(":", 1)
                if len(parts) == 2:
                    path = parts[1].strip()
                    if path and path != "/":
                        found.add(urljoin(base, path))
    # also try /sitemap.xml
    sitemap_guess = urljoin(base, "/sitemap.xml")
    s_status, s_text, _ = await fetch_text(session, sitemap_guess)
    if s_status and s_text:
        found.update(await parse_sitemap(session, sitemap_guess))
    return found

async def parse_sitemap(session: aiohttp.ClientSession, sitemap_url: str) -> Set[str]:
    """Parse sitemap (could be sitemap index)"""
    urls = set()
    try:
        status, text, _ = await fetch_text(session, sitemap_url)
        if not status or not text:
            return urls
        tree = etree.fromstring(text.encode("utf-8", errors="ignore"))
        # sitemap index
        for elem in tree.findall(".//{*}loc"):
            val = elem.text.strip() if elem.text else None
            if val:
                if val.endswith(".xml"):
                    # nested sitemap
                    sub = await parse_sitemap(session, val)
                    urls.update(sub)
                else:
                    urls.add(val)
    except Exception as e:
        logging.debug("parse_sitemap failed %s -> %s", sitemap_url, e)
    return urls

COMMON_PATHS = [
    "/admin", "/login", "/signup", "/register", "/api", "/api/v1", "/.git", "/wp-login.php", "/wp-admin",
    "/robots.txt", "/sitemap.xml", "/.env", "/config", "/admin/login", "/dashboard"
]

async def simple_crawl(session: aiohttp.ClientSession, root: str, seeds: Set[str], depth: int, concurrency: int) -> Set[str]:
    """
    Simple BFS crawl (only same-origin links, limited depth). Seeds are initial URLs.
    Returns set of discovered URLs.
    """
    discovered = set(seeds)
    to_visit = set(seeds)
    for d in range(depth):
        if not to_visit:
            break
        tasks = []
        sem = asyncio.Semaphore(concurrency)
        async def worker(u: str):
            async with sem:
                status, text, meta = await fetch_text(session, u)
                if not text:
                    return []
                soup = BeautifulSoup(text, "html.parser")
                urls = set()
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    # join relative
                    full = urljoin(u, href)
                    if is_same_origin(root, full):
                        urls.add(full.split('#')[0].rstrip('/'))
                return list(urls)
        coros = [worker(u) for u in list(to_visit)]
        results = await asyncio.gather(*coros)
        new = set()
        for res in results:
            new.update(res)
        new = new - discovered
        discovered.update(new)
        to_visit = new
    return discovered

def extract_query_param_names(url: str) -> List[str]:
    parsed = urlparse(url)
    q = parse_qs(parsed.query)
    return list(q.keys())

# ---------- Checks ----------

async def check_reflected_xss(session: aiohttp.ClientSession, endpoint: Endpoint, timeout:int) -> Optional[CheckFinding]:
    """
    Inject unique marker into each parameter; check if marker reflected (simple check).
    No JS payloads are used. Marker is unique and benign.
    """
    if not endpoint.params:
        return None
    marker = random_marker()
    findings = []
    for p in endpoint.params:
        parsed = urlparse(endpoint.url)
        qs = parse_qs(parsed.query)
        qs[p] = [marker]
        new_q = urlencode(qs, doseq=True)
        new = parsed._replace(query=new_q)
        test_url = urlunparse(new)
        status, text, meta = await fetch_text(session, test_url, timeout)
        if not status:
            continue
        if marker in (text or ""):
            # heuristic: reflected directly in response body
            findings.append(f"param={p}")
    if findings:
        return CheckFinding(issue="Reflected XSS (possible reflection)", severity="medium",
                            detail=f"Reflected marker in params: {', '.join(findings)}", evidence=marker)
    return None

async def check_sqli_boolean(session: aiohttp.ClientSession, endpoint: Endpoint, timeout:int) -> Optional[CheckFinding]:
    """
    Safe boolean-based SQLi test: for each param send a 'true' payload and a 'false' payload
    and compare responses. Non-destructive.
    """
    if not endpoint.params:
        return None
    true_payload = "' OR '1'='1"
    false_payload = "' AND '1'='2"
    findings = []
    for p in endpoint.params:
        parsed = urlparse(endpoint.url)
        qs = parse_qs(parsed.query)
        original = qs.get(p, [""])[0]
        qs[p] = [original + true_payload]
        url_true = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        status_t, text_t, _ = await fetch_text(session, url_true, timeout)
        qs[p] = [original + false_payload]
        url_false = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        status_f, text_f, _ = await fetch_text(session, url_false, timeout)
        if status_t and status_f:
            # compare bodies roughly
            if text_t and text_f and text_t != text_f:
                findings.append(p)
    if findings:
        return CheckFinding(issue="Possible boolean-based SQLi", severity="high",
                            detail=f"Parameters showing differential responses: {', '.join(findings)}",
                            evidence="difference detected")
    return None

async def check_open_redirect(session: aiohttp.ClientSession, endpoint: Endpoint, timeout:int) -> Optional[CheckFinding]:
    """
    Test typical redirect params. Inject SAFE URL (example.com). If server responds with 3xx Location to example.com
    or final resolved page contains example.com, it's an open-redirect.
    """
    redirect_param_candidates = ["next", "redirect", "url", "return", "r", "goto"]
    parsed = urlparse(endpoint.url)
    qs_base = parse_qs(parsed.query)
    found = []
    for p in (endpoint.params or []):
        if p.lower() in redirect_param_candidates:
            qs = dict(qs_base)
            qs[p] = [SAFE_REDIRECT_TARGET]
            test = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            try:
                async with session.get(test, timeout=ClientTimeout(total=timeout), allow_redirects=False) as resp:
                    # check 3xx Location header
                    loc = resp.headers.get("Location", "")
                    if loc and "example.com" in loc:
                        found.append(p)
                        continue
                # if no 3xx, follow and check final
                status, text, meta = await fetch_text(session, test, timeout)
                final = meta.get("final_url") if meta else ""
                if final and "example.com" in final:
                    found.append(p)
            except Exception:
                continue
    if found:
        return CheckFinding(issue="Open Redirect", severity="medium",
                            detail=f"Params allowing redirect to external target: {', '.join(found)}",
                            evidence=f"redirect target: {SAFE_REDIRECT_TARGET}")
    return None

# ---------- Orchestration ----------

async def analyze_target(target: str, *, concurrency:int, crawl_depth:int, timeout:int) -> List[EndpointResult]:
    target_norm = normalize_target(target)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    headers = {"User-Agent": USER_AGENT}
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        discovered = set()
        # seed: target root
        discovered.add(target_norm)
        # add common paths
        for p in COMMON_PATHS:
            discovered.add(urljoin(target_norm, p))
        # robots + sitemap
        robots_and_map = await discover_robots_and_sitemap(session, target_norm)
        discovered.update(robots_and_map)
        # crawl
        crawled = await simple_crawl(session, target_norm, set([target_norm]), depth=crawl_depth, concurrency=concurrency)
        discovered.update(crawled)
        # normalize
        discovered = set(x.rstrip("/") for x in discovered if x.startswith("http"))
        # reduce duplicates and sort
        urls = sorted(discovered)

        # Build endpoints list with query params
        endpoints: List[Endpoint] = []
        for u in urls:
            params = extract_query_param_names(u)
            endpoints.append(Endpoint(url=u, method="GET", params=params))

        # run checks concurrently over endpoints
        sem = asyncio.Semaphore(concurrency)
        async def worker(ep: Endpoint) -> EndpointResult:
            async with sem:
                res = EndpointResult(endpoint=ep, raw_responses={})
                # run checks
                try:
                    res.open_redirect = await check_open_redirect(session, ep, timeout)
                except Exception as e:
                    logging.debug("open_redirect error %s %s", ep.url, e)
                try:
                    res.reflected_xss = await check_reflected_xss(session, ep, timeout)
                except Exception as e:
                    logging.debug("xss error %s %s", ep.url, e)
                try:
                    res.sqli = await check_sqli_boolean(session, ep, timeout)
                except Exception as e:
                    logging.debug("sqli error %s %s", ep.url, e)
                return res

        tasks = [worker(ep) for ep in endpoints]
        results: List[EndpointResult] = []
        for f in asyncio.as_completed(tasks):
            try:
                r = await f
                results.append(r)
            except Exception as e:
                logging.debug("endpoint worker failed: %s", e)
        return results

# ---------- Reporting ----------
HTML_TMPL = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Endpoint Check Report</title>
<style>
body{font-family:Inter, Arial, sans-serif; max-width:980px; margin:24px auto}
h1{font-size:20px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px;font-size:13px}
th{background:#f4f4f4}
.bad{color:#a00}
.good{color:#080}
</style></head>
<body>
<h1>Endpoint Check Report - {{target}}</h1>
<p>Generated: {{generated}}</p>
<p>Summary: total endpoints checked: {{total}}</p>
<table>
<thead><tr><th>Endpoint</th><th>Open-Redirect</th><th>Reflected XSS</th><th>SQLi (bool)</th></tr></thead>
<tbody>
{% for r in results %}
<tr>
  <td><a href="{{r.endpoint.url}}" target="_blank">{{r.endpoint.url}}</a></td>
  <td>{% if r.open_redirect %}<span class="bad">{{r.open_redirect.detail}}</span>{% else %}—{% endif %}</td>
  <td>{% if r.reflected_xss %}<span class="bad">{{r.reflected_xss.detail}}</span>{% else %}—{% endif %}</td>
  <td>{% if r.sqli %}<span class="bad">{{r.sqli.detail}}</span>{% else %}—{% endif %}</td>
</tr>
{% endfor %}
</tbody>
</table>
</body>
</html>
"""

def save_reports(results: List[EndpointResult], out_basename: str, target: str):
    # JSON
    json_path = f"{out_basename}.json"
    obj = {
        "target": target,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "results": []
    }
    for r in results:
        obj["results"].append({
            "endpoint": r.endpoint.url,
            "params": r.endpoint.params,
            "open_redirect": asdict(r.open_redirect) if r.open_redirect else None,
            "reflected_xss": asdict(r.reflected_xss) if r.reflected_xss else None,
            "sqli": asdict(r.sqli) if r.sqli else None,
        })
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
    # HTML
    html_path = f"{out_basename}.html"
    tpl = Template(HTML_TMPL)
    html = tpl.render(target=target, generated=obj["generated"], total=len(results), results=results)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return json_path, html_path

# ---------- CLI ----------
def build_parser():
    p = argparse.ArgumentParser(prog="endpoint-checker", description="Discover endpoints and run safe checks (XSS/SQLi/open-redirect).")
    p.add_argument("-t", "--targets", required=True, help="Comma-separated list of targets (domain or URL). e.g. example.com or https://example.com")
    p.add_argument("-o", "--output", default="endpoint_report", help="Output basename (adds .json and .html)")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--crawl-depth", type=int, default=DEFAULT_CRAWL_DEPTH, help="Depth for HTML crawl (0 = no crawl)")
    p.add_argument("--verbose", "-v", action="count", default=0)
    return p

def setup_logging(v: int):
    lvl = logging.WARNING
    if v >= 2:
        lvl = logging.DEBUG
    elif v == 1:
        lvl = logging.INFO
    logging.basicConfig(level=lvl, format="%(asctime)s [%(levelname)s] %(message)s")

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)
    print("WARNING: Only scan systems you own or are authorized to test.")
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    loop = asyncio.get_event_loop()
    all_results = []
    for tgt in targets:
        # Print the RECON banner before starting the analysis for each target
        try:
            print_banner(tgt)
        except Exception:
            # banner should not break execution; fallback to a simple line
            print(f"[+] Analyzing {tgt} ...")
        print(f"[+] Analyzing {tgt} ...")
        results = loop.run_until_complete(analyze_target(tgt, concurrency=args.concurrency, crawl_depth=args.crawl_depth, timeout=args.timeout))
        jsonpath, htmlpath = save_reports(results, f"{args.output}_{urlparse(normalize_target(tgt)).hostname}", tgt)
        print(f"[+] Outputs: {jsonpath} , {htmlpath}")
        print(f"[+] Endpoints checked: {len(results)}")
        all_results.extend(results)
    print("[*] Done.")

if __name__ == "__main__":
    main()
