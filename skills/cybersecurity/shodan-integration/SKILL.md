---
name: shodan-integration
description: "Shodan integration for cybersecurity workflows — attack surface management, OSINT, vulnerability enrichment, asset discovery, and incident response. Use when investigating exposed services, querying external assets, monitoring network perimeters, or correlating CVE data with internet-facing infrastructure."
---

# Shodan Integration

Shodan is the **search engine for internet-connected devices**. Unlike Google which indexes web pages, Shodan indexes **banners** — the metadata services return when they connect. Every open port, exposed service, and misconfigured device on the public internet gets cataloged.

This skill covers:
- API surface (REST + Streaming)
- Search filter syntax (60+ filters)
- Python library and CLI usage
- Cybersecurity applications
- AI agent integration patterns

## When to Use This Skill

| Scenario | Shodan role |
|----------|-------------|
| **External attack surface audit** | Discover all your org's assets visible on the public internet |
| **Vulnerability prioritization** | Find which of your assets are running vulnerable versions |
| **OSINT on threat actor infra** | Pivot from an IP/domain to all other assets on the same netblock/ASN |
| **Incident response** | Check if a compromised system shows up on Shodan (it usually does) |
| **Vendor/third-party risk** | Assess security posture of a third party before contract |
| **Compliance evidence** | Document exposed services for PCI-DSS, ISO 27001 A.5.9 (inventory of assets), NIST CSF ID.AM |
| **Red team recon** | Initial attack surface enumeration before engagement |

## When NOT to Use

- Internal/private IP ranges (RFC 1918): Shodan doesn't index these. Use Nmap/Zenmap instead.
- Web app vulnerability scanning: Shodan doesn't crawl authenticated content. Use Burp/ZAP.
- Source code review: Not Shodan's domain.

## API Surface

### Base URL
`https://api.shodan.io`

### Authentication
Every request requires `key=YOUR_API_KEY` query param or `Authorization: Bearer YOUR_API_KEY` header.

API keys are obtained from https://account.shodan.io — separate from a paid Membership.

### Plan Limits (developer tier reference, verify before relying)

| Tier | Query credits/mo | Monitor IPs | Scan credits/mo | Rate limit |
|------|-----------------|-------------|-----------------|------------|
| Free | 100 | 0 | 0 | 1 req/s |
| Membership ($69) | 10,000 | 5 | 100 | 1 req/s |
| Developer API ($59) | 100,000 | 0 | 10,000 | 1 req/s |
| Enterprise | Custom | Custom | Custom | Custom |

### Core Endpoints

| Method | Endpoint | Purpose | Cost (credits) |
|--------|----------|---------|----------------|
| GET | `/shodan/host/{ip}` | All info on one IP | 1 |
| GET | `/shodan/host/{ip}/history` | Historical banners for an IP | 1 |
| GET | `/shodan/host/{ip}/dns` | Reverse DNS info | 1 |
| GET | `/shodan/host/{ip}/services` | Service-level breakdown | 1 |
| GET | `/shodan/host/{ip}/vulns` | CVEs for an IP | 1 |
| GET | `/shodan/search` | Search query | 1 |
| GET | `/shodan/search/count` | Count only, no results | 0 |
| GET | `/shodan/search/facets` | Available facet values | 0 |
| GET | `/shodan/search/tokens` | Parse a query into tokens | 0 |
| GET | `/shodan/exploits/search` | Search exploit DB | 1 |
| GET | `/shodan/exploits/count` | Count exploit results | 0 |
| GET | `/shodan/labs/honeyscore` | Prob a honeypot (0-1) | 1 |
| GET | `/shodan/dns/domain` | Subdomains for domain | 1 |
| GET | `/shodan/dns/resolve` | Resolve hostnames | 1 |
| GET | `/shodan/dns/reverse` | Reverse DNS for IPs | 1 |
| GET | `/shodan/tools/httpheaders` | HTTP headers test | 1 |
| GET | `/shodan/tools/myip` | Your public IP | 0 |
| GET | `/shodan/account/profile` | Plan info, query credits | 0 |
| GET | `/shodan/api-info` | Plan info | 0 |
| GET | `/shodan/data` | List available datasets | 0 |
| GET | `/shodan/data/{dataset}` | Stream a dataset | varies |
| WS | `/shodan/stream` | Real-time banner stream | query-credit subscription |
| WS | `/shodan/stream/asn/{asn}` | Stream filtered to ASN | subscription |
| WS | `/shodan/stream/ports/{port}` | Stream filtered to port | subscription |
| WS | `/shodan/stream/alert` | Monitor alerts | subscription |
| GET | `/alert` | Manage Monitor alerts | 0 |
| GET | `/notifier` | Manage alert notifiers | 0 |
| GET | `/query` | Saved queries | 0 |
| GET | `/org` | Manage org members | 0 |
| GET | `/scan` | Request a Shodan scan | 1+ |
| GET | `/scan/internet` | Scan the whole internet (Enterprise) | varies |

### Streaming Endpoints

The Streaming API gives real-time banners as Shodan crawls. Requires Streaming subscription ($499+/mo).

```python
import shodan
api = shodan.Shodan(API_KEY)
for banner in api.stream.banners():
    # banner is a dict: ip, port, data, location, product, version, etc.
    print(f"{banner['ip']}:{banner['port']} - {banner.get('product', 'unknown')}")
```

Stream filters:
- `asn:AS15169` — Google
- `port:80,443`
- `product:nginx`
- `vuln:CVE-2021-44228`
- `geo:1.3521,103.8198` (Singapore coords)
- `ip:1.2.3.4`
- `net:192.168.0.0/16`

## Search Filter Syntax

Shodan search uses **key:value** pairs. Quoted strings support spaces.

### Network Filters

| Filter | Example | Description |
|--------|---------|-------------|
| `ip` | `ip:8.8.8.8` | Specific IP |
| `net` | `net:192.168.0.0/16` | CIDR block |
| `asn` | `asn:AS15169` | Autonomous System Number (with AS prefix) |
| `isp` | `isp:"Google LLC"` | Internet Service Provider |
| `org` | `org:"Acme Corp"` | Organization name (fuzzy) |
| `cidr` | `cidr:1.2.3.4/24` | CIDR with explicit prefix |

### Geographic Filters

| Filter | Example | Description |
|--------|---------|-------------|
| `country` | `country:US` | ISO 2-letter |
| `city` | `city:"San Francisco"` | City name |
| `region` | `region:CA` | State/province |
| `postal` | `postal:94107` | Postal code |
| `geo` | `geo:37.7749,-122.4194` | Lat,lon with radius |

### Service Filters

| Filter | Example | Description |
|--------|---------|-------------|
| `port` | `port:22` | Port number |
| `protocol` | `protocol:tcp` | tcp/udp |
| `transport` | `transport:http` | Same as protocol mostly |
| `product` | `product:nginx` | Detected software |
| `version` | `version:"1.18.0"` | Detected version |
| `os` | `os:"Windows Server 2019"` | Detected OS |
| `devicetype` | `devicetype:webcam` | Device category |
| `banner` | `banner:SSH-2.0` | Raw banner content |

### Web/HTTP Filters

| Filter | Example | Description |
|--------|---------|-------------|
| `http.title` | `http.title:"Dashboard"` | HTML title tag |
| `http.html` | `http.html:"login"` | HTML body content |
| `http.status` | `http.status:200` | HTTP response code |
| `http.component` | `http.component:jQuery` | Detected JS component |
| `http.favicon.hash` | `http.favicon.hash:116583819` | Favicon hash (find similar) |
| `http.headers` | `http.headers:"Strict-Transport-Security"` | Specific header presence |
| `http.server` | `http.server:cloudflare` | Server header |
| `ssl` | `ssl:true` | SSL/TLS available |
| `ssl.cert.subject.cn` | `ssl.cert.subject.cn:"example.com"` | Certificate CN |
| `ssl.cert.issuer.cn` | `ssl.cert.issuer.cn:"Let's Encrypt"` | Certificate issuer |
| `ssl.cert.expired` | `ssl.cert.expired:true` | Expired cert |
| `ssl.version` | `ssl.version:tlsv1.2` | TLS version |
| `ssl.cipher.name` | `ssl.cipher.name:"AES128-GCM"` | TLS cipher |

### Timing Filters

| Filter | Example | Description |
|--------|---------|-------------|
| `before` | `before:01/01/2024` | Banner seen before date |
| `after` | `after:01/01/2024` | Banner seen after date |

### Vulnerability Filters

| Filter | Example | Description |
|--------|---------|-------------|
| `vuln` | `vuln:CVE-2021-44228` | Specific CVE |
| `vuln.provider` | `vuln.provider:cve` | CVE source |
| `has_vuln` | `has_vuln:true` | Any known vuln |

### Content Filters

| Filter | Example | Description |
|--------|---------|-------------|
| `tag` | `tag:ics` | Shodan's classification tags |
| `tag:ics` | `tag:ics` | Industrial Control Systems |
| `tag:iot` | `tag:iot` | IoT devices |
| `tag:database` | `tag:database` | Database servers |

### Operators

- AND is implicit: `port:80 product:apache` = both
- OR: `port:22 OR port:3389`
- NOT: `-product:nginx` (exclude)
- Grouping: `(port:80 OR port:443) product:apache`
- Quoted strings: `org:"Acme Corp"` for spaces
- Regex: not supported in search syntax, use `hostname` instead

### Common High-Value Queries

```
# Find your organization's exposed assets (replace with your domain)
org:"Acme Corp" port:80,443,8080,8443

# Exposed RDP (Top 1 attack vector)
port:3389 country:US

# Log4j (CVE-2021-44228) on your net
net:203.0.113.0/24 vuln:CVE-2021-44228

# Exposed databases (no auth)
product:"MongoDB" port:27017 -authentication

# Exposed industrial control systems
tag:ics country:US

# Find all assets using a specific software version
product:apache version:"2.4.49"

# Phishing infrastructure with self-signed certs
ssl.cert.issuer.cn:"self-signed" http.title:"admin"
```

## Python Library

```bash
pip install shodan
```

```python
import shodan
import os

API_KEY = os.environ.get("SHODAN_API_KEY")
api = shodan.Shodan(API_KEY)

# === HOST LOOKUP ===
host = api.host("8.8.8.8")
print(host['ip_str'])
print(host.get('org', 'unknown'))
print(host.get('os', 'unknown'))
for item in host.get('data', []):
    print(f"  {item['port']}/{item['transport']}: {item.get('product', '')}")

# === SEARCH ===
results = api.search("apache country:US port:80", limit=100)
print(f"Total matches: {results['total']}")
for match in results['matches']:
    print(f"{match['ip_str']}:{match['port']} - {match.get('product', '')}")

# === COUNT (no credits) ===
count = api.count("vuln:CVE-2021-44228 country:US")
print(f"US hosts vulnerable to Log4j: {count['total']}")

# === FACETS ===
facets = api.search_facets("apache country:US")
# returns counts by port, org, product, version, etc.

# === EXPLOITS ===
exploits = api.exploits.search("log4j", limit=10)
for e in exploits['matches']:
    print(f"  {e.get('id', e.get('cve', 'unknown'))}: {e.get('description', '')[:80]}")

# === DNS ===
subdomains = api.dns.domain_info("example.com")
# Returns list of subdomains: ['www', 'mail', 'admin', ...]
# Note: shodan 1.31.0 only has api.dns.domain_info; no .resolve() or .reverse()
# Use api.host(ip) for reverse DNS - it includes 'hostnames' field

# For DNS resolution, use the REST API directly:
import urllib.request, json
req = urllib.request.Request("https://api.shodan.io/dns/resolve?hostnames=example.com,www.example.com&key=" + API_KEY)
with urllib.request.urlopen(req) as resp:
    resolved = json.loads(resp.read().decode())  # {"example.com": ["1.2.3.4"], ...}

req = urllib.request.Request("https://api.shodan.io/dns/reverse?ips=1.2.3.4,5.6.7.8&key=" + API_KEY)
with urllib.request.urlopen(req) as resp:
    reversed_dns = json.loads(resp.read().decode())  # list of {ip, hostname}

# === HONEYSCORE (is this IP a honeypot?) ===
score = api.labs.honeyscore("1.2.3.4")
# Returns 0.0 to 1.0; >0.5 is likely honeypot

# === HTTP HEADERS TEST ===
headers_info = api.tools.httpheaders("https://example.com")
# Returns dict with security headers analysis

# === STREAMING (requires subscription) ===
for banner in api.stream.banners():
    print(banner)
# Or filtered stream
for banner in api.stream.banners(asn="AS15169"):
    # only Google assets
    ...

# === ALERT MANAGEMENT ===
# List alerts
alerts = api.alerts()
# Create alert
alert = api.create_alert(
    name="acme-rdp-exposure",
    filters={"ip": ["203.0.113.0/24"], "port": 3389},
    expires=0,
)

# === SCAN REQUEST ===
scan = api.scan("203.0.113.0/24")
# On-demand scan of an IP block

# === DOWNTIME-AWARE RETRIES ===
# The library has built-in retries for 429 responses
```

## Command-Line Interface

```bash
# Install: pip install shodan, then:
shodan init YOUR_API_KEY

# Search
shodan search "apache country:US port:80" --limit 100
shodan search "vuln:CVE-2021-44228" --fields ip_str,port,org --limit 50

# Host lookup
shodan host 8.8.8.8

# Search with specific fields only
shodan search "product:nginx" --fields ip_str,port,version,org

# Download raw data
shodan host 8.8.8.8 --save

# My IP
shodan myip

# Filter stream to file (Streaming API)
shodan stream --asn AS15169 --limit 10000 > banners.jsonl

# Alert management
shodan alert create "acme-rdp" --ip 203.0.113.0/24 --port 3389
shodan alert list
shodan alert delete <alert_id>

# Stats
shodan info  # account info, query credits
shodan stats --facets port,org --limit 10 "country:US"
```

## Cybersecurity Use Cases

### 1. External Attack Surface Management (EASM)

Continuous discovery of all your org's internet-exposed assets.

```python
# Quarterly external attack surface scan
import shodan, os, json

api = shodan.Shodan(os.environ["SHODAN_API_KEY"])

# Discover by domain
domain_assets = api.dns.domain("example.com")
ips_to_scan = api.dns.resolve(domain_assets)

# Discover by org name (fuzzy match)
results = api.search(
    'org:"Acme Corp" -hostname:"*.example.com"',  # exclude what dns.domain found
    limit=500,
)

# Discover by ASN
asn_results = api.search("asn:AS64496", limit=500)

# Combine and deduplicate
all_ips = set(ips_to_scan.values()) | {r['ip_str'] for r in results['matches']}
```

Outputs feed into: vulnerability scanner, asset inventory CMDB, attack surface tools (CrowdStrike Falcon Surface, Tenable ASM, Microsoft Defender EASM).

### 2. Vulnerability Prioritization

```python
# Find exposed assets with critical CVEs
critical_cves = ["CVE-2021-44228", "CVE-2017-0144", "CVE-2019-0708"]

for cve in critical_cves:
    count = api.count(f"vuln:{cve} org:\"Acme Corp\"")
    if count['total'] > 0:
        # Trigger patch workflow
        send_to_patch_queue(cve, count['total'])
```

This shows you **internet-facing vulnerable assets**, which is what attackers actually see. Different from internal-only vuln scans.

### 3. OSINT and Threat Actor Infrastructure

```python
# Pivot from one IP to find related infra
host = api.host("1.2.3.4")  # suspected C2

# Same org
same_org = api.search(f'org:"{host["org"]}"', limit=100)

# Same ASN
same_asn = api.search(f'asn:{host["asn"]}', limit=100)

# Same subnet
subnet = host['ip_str'].rsplit('.', 1)[0] + '.0/24'
same_subnet = api.search(f"net:{subnet}", limit=100)

# Reverse DNS pattern
# If 1.2.3.4 has hostname mail.evilcorp.ru, search *.evilcorp.ru
reverse = api.dns.reverse([host['ip_str']])
```

### 4. Incident Response

```python
# Was the compromised system already known to Shodan?
host = api.host(compromised_ip)
if host:
    print(f"Exposed since: {host.get('data', [{}])[0].get('timestamp', 'unknown')}")
    print(f"Banners: {[item.get('product') for item in host.get('data', [])]}")
    # Tells you how long the asset has been visible
```

### 5. Vendor / Third-Party Risk

```python
# Acme Corp supplier security posture check
target_org = "Vendor Inc"
vulns = api.search(f'org:"{target_org}" has_vuln:true', limit=500)
exposed_ports = api.search(
    f'org:"{target_org}" port:3389 OR port:23 OR port:21',
    limit=500,
)
expired_certs = api.search(
    f'org:"{target_org}" ssl.cert.expired:true',
    limit=500,
)
# Score, report, escalate before contract signing
```

### 6. Red Team Recon

```python
# Initial recon for penetration test engagement
target = "client.com"

# Subdomain enumeration
subdomains = api.dns.domain(target)

# Exposed services
for sub in subdomains:
    try:
        host = api.host(sub)
        for item in host.get('data', []):
            print(f"{sub}:{item['port']} {item.get('product', '')} {item.get('version', '')}")
    except shodan.APIError:
        pass

# Find development/staging environments
dev_staging = api.search(f'http.title:"Coming Soon" OR http.title:"Test" org:"{target}"')

# Find forgotten admin panels
admin_panels = api.search(f'http.title:"admin" OR http.title:"login" org:"{target}"')
```

### 7. Honeypot Detection

```python
# Before kicking off recon, check if target is a honeypot
for ip in target_ips:
    score = api.labs.honeyscore(ip)
    if score > 0.5:
        print(f"WARNING: {ip} likely a honeypot ({score})")
```

### 8. Compliance Documentation (ISO 27001, NIST CSF)

ISO 27001:2022 A.5.9 — Inventory of information and other associated assets. NIST CSF ID.AM-1 — Physical devices and systems within the organization are inventoried.

Use Shodan to **document** the inventory:

```python
# Monthly asset inventory report
results = api.search('org:"Acme Corp"', limit=1000)
inventory = []
for r in results['matches']:
    inventory.append({
        'ip': r['ip_str'],
        'port': r['port'],
        'product': r.get('product'),
        'version': r.get('version'),
        'os': r.get('os'),
        'last_seen': r.get('timestamp'),
    })
save_to_compliance_db(inventory)
```

## Integration Patterns for AI Agents

### Pattern 1: Direct API Tool Calls

```python
def shodan_lookup_ip(ip: str) -> dict:
    """Look up information about an IP address via Shodan."""
    api = shodan.Shodan(os.environ["SHODAN_API_KEY"])
    try:
        host = api.host(ip)
        return {
            "ip": host["ip_str"],
            "org": host.get("org"),
            "asn": host.get("asn"),
            "os": host.get("os"),
            "ports": [item["port"] for item in host.get("data", [])],
            "hostnames": host.get("hostnames", []),
            "city": host.get("city"),
            "country": host.get("country_name"),
            "vulns": host.get("vulns", []),
            "tags": host.get("tags", []),
        }
    except shodan.APIError as e:
        return {"error": str(e)}
```

### Pattern 2: Query Credit Budgeting

```python
class ShodanClient:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
        self.credits_used = 0
        self.budget = int(os.environ.get("SHODAN_DAILY_BUDGET", 1000))

    def search(self, query, limit=100):
        if self.credits_used >= self.budget:
            return {"error": "daily budget exceeded", "matches": []}
        result = self.api.search(query, limit=limit)
        self.credits_used += 1
        return result
```

### Pattern 3: Caching Layer

Shodan data doesn't change minute-to-minute. Cache aggressively.

```python
import redis
from datetime import timedelta

cache = redis.Redis()
TTL = timedelta(hours=24)

def cached_search(query, limit=100):
    key = f"shodan:search:{hash(query)}:{limit}"
    cached = cache.get(key)
    if cached:
        return json.loads(cached)
    result = api.search(query, limit=limit)
    cache.setex(key, TTL, json.dumps(result))
    return result
```

### Pattern 4: Streaming for Real-Time Monitoring

```python
# In a long-running agent, attach a callback to the stream
def on_banner(banner):
    if banner.get('org') == 'Acme Corp':
        alert_security_team(f"New {banner.get('product')} on {banner['ip']}:{banner['port']}")

api.stream.banners(callback=on_banner)
```

### Pattern 5: Faceted Dashboards

```python
# Build a dashboard of your attack surface
facets = api.search_facets('org:"Acme Corp"', facets=["port", "product", "version", "vuln", "ssl.cert.expired"])
# Returns nested counts for drill-down
```

## Self-Protection Rule (CRITICAL)

When using Shodan through AI agent workflows:

1. **API key in env var only**, never in code or logs
2. **Never expose query results containing third-party data** outside the authorized security investigation
3. **Never scan random IPs** without authorization — only scan assets you own or have explicit permission to test
4. **Honor rate limits** — 1 req/sec on free/dev plans; exceeding gets you IP-banned temporarily
5. **Don't use Shodan as a port scanner** — that's not what it's for, and on-demand scans cost credits
6. **Restrict scan permissions** to specific org names/ASNs in agent prompts to prevent the agent from going rogue

## Gotchas and Limitations

| Gotcha | Details |
|--------|---------|
| **No internal IP coverage** | RFC 1918 ranges are not indexed |
| **Banners can be stale** | An IP might show old data if it changed ownership |
| **HTTPS introspection is limited** | Only cert metadata, not request/response |
| **CVEs may be false positives** | The `vuln:` filter is banner-based, not exploit-verified |
| **Honeypot false positives** | `honeyscore` is heuristic, not definitive |
| **Free tier is restrictive** | 100 query credits/month — design carefully |
| **No bulk download without Enterprise** | Streaming is the workaround but expensive |
| **Search syntax quirks** | `org:` is fuzzy match; `asn:` requires `AS` prefix |
| **IPv6 support is limited** | Many filters don't work for IPv6 |
| **Historical data costs extra** | `/host/{ip}/history` is query credits AND historical credits |

## Ethical and Legal Considerations

- **CFAA / Computer Fraud and Abuse Act (US)**: Shodan searches are passive observation of public banners, generally legal
- **GDPR**: Banner data may contain personal info; minimize storage, document retention
- **Corporate policy**: Always get written authorization before querying your own org's exposure
- **Third-party data**: Don't republish Shodan data showing third-party vulnerabilities
- **Sanctions compliance**: Be careful with queries against embargoed countries (Cuba, Iran, North Korea, etc.)
- **Documentation**: For audit, log every query made, the operator, the case ID, and the justification

## Configuration
## Verified Environment (2026-06-20)

Real data captured against a live Developer API account (`$59/mo`, 100 query credits/mo):

| Component | Verified Value |
|-----------|----------------|
| **Plan** | dev |
| **Library version** | shodan 1.31.0 (Python) |
| **Library API** | `api.host`, `api.search`, `api.count`, `api.info`, `api.dns.domain_info`, `api.labs.honeyscore`, `api.tools.myip`, `api.stream.banners` |
| **Auth method** | URL query param `?key=*** (Bearer header returns 401 on this account) |
| **8.8.8.8** | Google LLC, AS15169, Mountain View, dns.google, ports 53/443 |
| **Log4Shell worldwide** | 6 hosts still showing CVE-2021-44228 in banners |
| **Google search `org:Google port:80,443`** | 3,473,968 matches |
| **google.com subdomains** | 32 enumerated via `api.dns.domain_info` |
| **Honeyscore on 8.8.8.8** | 0.0 (real, not honeypot) |

**Library API gotcha:** `api.dns.resolve()` and `api.dns.reverse()` were removed in shodan 1.31.0. Only `api.dns.domain_info()` remains. For IP↔hostname lookups, use the REST API directly (`/dns/resolve`, `/dns/reverse`) or rely on `api.host()`'s `hostnames` field.

## Configuration

### Environment Variables

```bash
export SHODAN_API_KEY="your...port SHODAN_DAILY_BUDGET=50        # max query credits per day for agent use
export SHODAN_ORG_ALLOWLIST="SapphireGuard|Acme Corp"  # only allow queries for these orgs
```

### Verify Setup

```bash
# Install library
pip install shodan  # or: uv pip install shodan

# Quick test (URL query param works on dev plan)
python3 -c "
import shodan
api = shodan.Shodan('YOUR_KEY')
print(api.tools.myip())
print(api.info())
"

# Or with env file
set -a && source /tmp/shodan.env && set +a
python3 -c "
import shodan, os
api = shodan.Shodan(os.environ['SHODAN_API_KEY'])
print(api.info())
"

## Related Tools

- **Censys** — alternative search engine, similar scope, different indexing
- **FOFA** — Chinese alternative, broader Asia-Pacific coverage
- **BinaryEdge** — another internet scanning engine
- **ZoomEye** — Chinese alternative
- **Hunter.io** — email/host OSINT
- **SecurityTrails** — historical DNS
- **VirusTotal** — file/URL malware analysis
- **GreyNoise** — internet scanner/background noise identification
- **Censys Search 2.0** — modern Censys API
- **ipinfo.io** — IP geolocation and ASN
- **bgp.he.net** — BGP routing lookup
- **RIPE/ARIN/APNIC** — IP allocation registries

## Cross-References

- **ISO 27001:2022 A.5.9** — Inventory of information and associated assets (use Shodan for external inventory)
- **ISO 27001:2022 A.5.7** — Threat intelligence (Shodan as one source)
- **NIST CSF ID.AM-1** — Physical devices and systems inventoried
- **NIST CSF ID.AM-3** — Organizational communication and data flows inventoried
- **NIST CSF DE.CM-1** — Network is monitored for cybersecurity events
- **MITRE ATT&CK T1595** — Active Scanning: Vulnerability Scanning (Shodan = passive alternative)
- **MITRE ATT&CK T1590** — Gather Victim Network Information