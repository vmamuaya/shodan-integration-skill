# Shodan Integration Skill for Hermes Agent

Comprehensive Shodan integration for cybersecurity workflows — attack surface management, OSINT, vulnerability enrichment, asset discovery, and incident response.

## What's Included

| File | Purpose |
|------|---------|
| `skills/cybersecurity/shodan-integration/SKILL.md` | The full skill file (22.5KB) |

## What is Shodan

Shodan is the **search engine for internet-connected devices**. Unlike Google which indexes web pages, Shodan indexes **banners** — the metadata services return when they connect. Every open port, exposed service, and misconfigured device on the public internet gets cataloged.

## Use Cases

- **External Attack Surface Management (EASM)** — discover all your org's internet-exposed assets
- **Vulnerability Prioritization** — find which exposed assets are running vulnerable versions
- **OSINT / Threat Intelligence** — pivot from an IP/domain to all other assets on the same netblock/ASN
- **Incident Response** — check if a compromised system shows up on Shodan
- **Vendor / Third-Party Risk** — assess security posture of a third party before contract
- **Red Team Recon** — initial attack surface enumeration before engagement
- **Compliance Documentation** — ISO 27001 A.5.9, NIST CSF ID.AM-1

## Installation

Copy `skills/cybersecurity/shodan-integration/SKILL.md` to your Hermes skills directory:

```bash
mkdir -p ~/.hermes/skills/cybersecurity/shodan-integration/
cp skills/cybersecurity/shodan-integration/SKILL.md ~/.hermes/skills/cybersecurity/shodan-integration/
```

Then load it:

```
/skill_load shodan-integration
```

## Configuration

```bash
export SHODAN_API_KEY="your-key-from-shodan-account"
export SHODAN_DAILY_BUDGET=1000     # max query credits per day for agent use
export SHODAN_ORG_ALLOWLIST="Acme Corp|Acme Inc"  # only allow queries for these orgs
```

## Skill Contents

- **API reference** — all REST + Streaming endpoints
- **Search filter syntax** — 60+ filters (network, geographic, service, HTTP, SSL, vuln, timing)
- **Python library** — full coverage with code examples
- **CLI tool** — `shodan init/search/host/stream/alert`
- **8 cybersecurity use cases** with production-ready code
- **5 AI agent integration patterns** (direct calls, credit budgeting, caching, streaming, faceted dashboards)
- **Self-protection rules** (key management, query permissions, rate limits)
- **Gotchas and limitations** table
- **Ethical and legal considerations** (CFAA, GDPR, sanctions)
- **ISO 27001 / NIST CSF / MITRE ATT&CK cross-references**

## Related

- Hermes Agent: https://github.com/sapphireguard/hermes-agent
- Shodan: https://www.shodan.io
- Shodan Developer API: https://developer.shodan.io
- Shodan Python library: https://shodan.readthedocs.io

## License

MIT — use freely, attribution appreciated.