"""
Source adapters. Each returns a list of IPv4 strings.
`auth: none` sources run without keys. `auth: key` sources skip cleanly if env missing.
"""
import os, re, json, time, logging, socket
import requests
import dns.resolver
from bs4 import BeautifulSoup

log = logging.getLogger("sources")
UA = "smc-scraper/1.0 (+https://example.invalid)"
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def _get(url, **kw):
    kw.setdefault("timeout", 15)
    kw.setdefault("headers", {"User-Agent": UA})
    return requests.get(url, **kw)


# ---------- zero-key sources ----------
def src_crt_sh(cfg):
    r = _get(cfg["url"])
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    hosts = set()
    for entry in r.json():
        for nv in (entry.get("name_value") or "").splitlines():
            nv = nv.strip().lstrip("*.")
            if nv: hosts.add(nv)
    ips = set()
    for h in list(hosts)[:300]:
        try:
            for a in socket.getaddrinfo(h, None, socket.AF_INET):
                ips.add(a[4][0])
        except socket.gaierror:
            pass
    return list(ips)


def src_grep_app(cfg):
    r = _get(cfg["url"])
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    body = r.text or ""
    return list(set(IPV4.findall(body)))


def src_github_code(cfg):
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    r = _get(cfg["url"], headers=h)
    if r.status_code == 403: raise RuntimeError("rate limited (set GITHUB_TOKEN)")
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    return list(set(IPV4.findall(r.text or "")))


def src_indexof(cfg):
    # Google blocks scripted queries aggressively; treat as best-effort.
    r = _get(cfg["url"], headers={"User-Agent": UA})
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    return list(set(IPV4.findall(r.text or "")))


def src_reverse_dns(cfg):
    cidrs_path = cfg.get("cidrs_source", "cidrs.txt")
    ips = set()
    try:
        with open(cidrs_path) as f:
            cidrs = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        raise RuntimeError(f"missing {cidrs_path}")
    import ipaddress
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2; resolver.lifetime = 3
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        for ip in list(net.hosts())[:5000]:
            arpa = ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
            try:
                ans = resolver.resolve(arpa, "PTR")
                if any(cfg.get("filter_substring", "ipmi") in str(r).lower() for r in ans):
                    ips.add(str(ip))
            except Exception:
                continue
    return list(ips)


def src_pastebin(cfg):
    r = _get(cfg["url"])
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    data = r.json()
    ips = set()
    for p in data[:50]:
        try:
            raw = _get(p["scrape_url"])
            if raw.status_code == 200:
                ips.update(IPV4.findall(raw.text or ""))
        except Exception:
            continue
    return list(ips)


def src_github_issues(cfg):
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    r = _get(cfg["url"], headers=h)
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    return list(set(IPV4.findall(r.text or "")))


# ---------- key sources (skip cleanly when absent) ----------
def _need(cfg, env):
    v = os.environ.get(env)
    if not v: raise RuntimeError(f"disabled: no {env}")
    return v


def src_shodan(cfg):
    key = _need(cfg, cfg["key_env"])
    r = _get("https://api.shodan.io/shodan/host/search",
             params={"key": key, "query": cfg["query"]})
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    return [m["ip_str"] for m in r.json().get("matches", [])]


def src_censys(cfg):
    _need(cfg, cfg["key_env"]); _need(cfg, cfg["key_env2"])
    r = _get("https://search.censys.io/api/v2/hosts/search",
             params={"q": cfg["query"]},
             auth=(os.environ[cfg["key_env"]], os.environ[cfg["key_env2"]]))
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    return [h["ip"] for h in r.json().get("result", {}).get("hits", [])]


def src_fofa(cfg):
    _need(cfg, cfg["key_env"]); _need(cfg, cfg["key_env2"])
    import base64
    q = base64.b64encode(cfg["query"].encode()).decode()
    r = _get("https://fofa.info/api/v1/search/all",
             params={"email": os.environ[cfg["key_env"]],
                     "key": os.environ[cfg["key_env2"]],
                     "qbase64": q, "fields": "ip", "size": 100})
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    return [x[0] if isinstance(x, list) else x for x in r.json().get("results", [])]


def src_zoomeye(cfg):
    key = _need(cfg, cfg["key_env"])
    r = _get("https://api.zoomeye.org/host/search",
             params={"query": cfg["query"]},
             headers={"API-KEY": key})
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    return [m["ip"] for m in r.json().get("matches", [])]


def src_netlas(cfg):
    key = _need(cfg, cfg["key_env"])
    r = _get("https://app.netlas.io/api/responses/",
             params={"q": cfg["query"]},
             headers={"X-API-Key": key})
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    return [i.get("data", {}).get("ip") for i in r.json().get("items", []) if i.get("data", {}).get("ip")]


def src_onyphe(cfg):
    key = _need(cfg, cfg["key_env"])
    r = _get("https://www.onyphe.io/api/v2/search",
             params={"q": cfg["query"], "size": 100},
             headers={"Authorization": f"Bearer {key}"})
    if r.status_code != 200: raise RuntimeError(f"HTTP {r.status_code}")
    return [x.get("ip") for x in r.json().get("results", []) if x.get("ip")]


HANDLERS = {
    "cert_transparency": lambda c: src_crt_sh(c),
    "code_search": lambda c: (src_github_code(c) if "api.github.com" in c["url"]
                              else src_grep_app(c)),
    "open_directory": src_indexof,
    "dns_ptr": src_reverse_dns,
    "paste_search": src_pastebin,
    "shodan": src_shodan, "censys": src_censys, "fofa": src_fofa,
    "zoomeye": src_zoomeye, "netlas": src_netlas, "onyphe": src_onyphe,
}


def run_source(cfg):
    fn = HANDLERS.get(cfg["kind"])
    if not fn: raise RuntimeError(f"unknown kind {cfg['kind']}")
    return fn(cfg)
