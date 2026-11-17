# vuln-intel-mcp

[![CI](https://github.com/raulsidii/vuln-intel-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/raulsidii/vuln-intel-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A **Model Context Protocol server** that gives AI assistants such as Claude Desktop and Claude Code live vulnerability intelligence for triage. It pulls from **NVD**, **FIRST EPSS** and **CISA KEV**, then ranks CVEs with a transparent, risk-based priority score.

**MCP in one line:** an open protocol that lets an AI assistant call external tools and data sources through a standard interface. This server is one of those tools.

## Why this exists: CVSS alone is not a priority

Scanners hand you hundreds of "CRITICAL" findings. CVSS measures **how bad a bug could be**, not **how likely it is to be used against you**. Patching by CVSS alone means spending most of the effort on bugs nobody exploits while real ones wait in the queue.

Three signals together give a much better answer:

| Signal | Source | Question it answers |
|---|---|---|
| **CVSS** | [NVD](https://nvd.nist.gov/developers/vulnerabilities) | How severe is the impact if exploited? |
| **EPSS** | [FIRST.org](https://www.first.org/epss/) | How likely is exploitation activity in the next 30 days? (a model's probability) |
| **KEV** | [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Is it *already* being exploited in the wild? (evidence) |

In the live run below, three CVEs are all rated CVSS 9.1 to 9.8 CRITICAL. One of them (curl SOCKS5, CVE-2023-38545) has a 78% EPSS; the other two sit below 4%. CVSS treats them almost identically. This server doesn't.

## Tools

| Tool | Input | Returns |
|---|---|---|
| `lookup_cve` | `cve_id`, `max_references?` (default 10) | NVD description, CVSS v4.0 / v3.1 / v2 score + vector, CWE, status, dates, references |
| `epss_score` | `cve_ids[]` (1-100) | EPSS probability, percentile and model date per CVE |
| `is_known_exploited` | `cve_ids[]` (1-100) | KEV listing: date added, federal due date, required action, ransomware use |
| `prioritize_cves` | `cve_ids[]` (1-30) | Ranked table with tier, 0-100 score and a one-line rationale per CVE |
| `search_cves` | `keyword`, `limit?` (1-20, default 5), `exact_match?` | Matching CVE IDs with CVSS, publish date and summary |

All tools are read-only (`readOnlyHint: true`). CVE IDs are validated and normalized (`cve-2021-44228` works too).

## Install

Requires Node.js 20 or newer to run (22.12+ to run the test suite).

```bash
git clone https://github.com/raulsidii/vuln-intel-mcp.git
cd vuln-intel-mcp
npm install
npm run build
```

### Optional: NVD API key

Without a key, NVD allows **5 requests per 30 seconds**; with one, 50. The server paces itself to stay under the limit, so a 20-CVE `prioritize_cves` call takes about two minutes without a key and a few seconds with one. Get a free key at <https://nvd.nist.gov/developers/request-an-api-key> and pass it as `NVD_API_KEY`.

### Claude Code

```bash
claude mcp add vuln-intel -- node /absolute/path/to/vuln-intel-mcp/dist/index.js

# with an NVD API key, available in every project:
claude mcp add vuln-intel --scope user -e NVD_API_KEY=your-key -- node /absolute/path/to/vuln-intel-mcp/dist/index.js
```

Check it with `claude mcp list`, or `/mcp` inside a session.

### Claude Desktop

Edit `claude_desktop_config.json` (Settings → Developer → Edit Config):

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "vuln-intel": {
      "command": "node",
      "args": ["/absolute/path/to/vuln-intel-mcp/dist/index.js"],
      "env": {
        "NVD_API_KEY": "optional-your-key"
      }
    }
  }
}
```

On Windows, use escaped backslashes or forward slashes in the path, e.g. `"C:/Users/you/vuln-intel-mcp/dist/index.js"`. Restart Claude Desktop after saving.

## Example conversation

The tool output below is real (captured on 2026-11-17 with `npm run smoke`). The assistant's wording is an example of what a client does with it.

**User:** Our scanner flagged these on the edge fleet: CVE-2023-38545, CVE-2024-45337, CVE-2021-44228, CVE-2024-24790, CVE-2024-3400. Four of them say CRITICAL. What do we fix first?

*Assistant calls `prioritize_cves` with the five IDs:*

| # | CVE | Tier | Score | KEV | EPSS | CVSS | Rationale |
|---|---|---|---|---|---|---|---|
| 1 | CVE-2021-44228 | CRITICAL | 100.0 | yes (ransomware) | 99.9% | 10.0 (v3.1) | Patch now — exploited in the wild: CISA KEV since 2021-12-10 (ransomware use), EPSS 99.9% (p100.0), CVSS 10.0 CRITICAL. |
| 2 | CVE-2024-3400 | CRITICAL | 100.0 | yes (ransomware) | 99.9% | 10.0 (v3.1) | Patch now — exploited in the wild: CISA KEV since 2024-04-12 (ransomware use), EPSS 99.9% (p100.0), CVSS 10.0 CRITICAL. |
| 3 | CVE-2023-38545 | HIGH | 86.2 | no | 78.3% | 9.8 (v3.1) | Patch soon — exploitation highly likely: not in KEV, EPSS 78.3% (p99.5), CVSS 9.8 CRITICAL. |
| 4 | CVE-2024-24790 | MEDIUM | 40.4 | no | 1.9% | 9.8 (v3.1) | Schedule — severe on paper, but low exploitation likelihood: not in KEV, EPSS 1.9% (p80.6), CVSS 9.8 CRITICAL. |
| 5 | CVE-2024-45337 | MEDIUM | 38.7 | no | 3.7% | 9.1 (v3.1) | Schedule — severe on paper, but low exploitation likelihood: not in KEV, EPSS 3.7% (p90.1), CVSS 9.1 CRITICAL. |

**Assistant:** Two of these are emergencies, not just "critical":

1. **CVE-2021-44228 (Log4Shell)** and **CVE-2024-3400 (PAN-OS GlobalProtect)** are both in CISA's Known Exploited Vulnerabilities catalog with known ransomware use. Patch or mitigate today, starting with whatever is internet-facing. The PAN-OS box is the perimeter itself, so if it's exposed, treat it as first and check for compromise, not just the patch.
2. **CVE-2023-38545 (curl SOCKS5 heap overflow)** isn't in KEV, but EPSS puts it at 78% for exploitation activity in the next 30 days. Put it in this week's patch cycle.
3. **CVE-2024-24790 (Go `net/netip`)** and **CVE-2024-45337 (Go `x/crypto/ssh` misuse)** score 9.8 and 9.1, but their EPSS is under 4%, and 45337 only bites if your code misuses `PublicKeyCallback`. Schedule them with the normal dependency bump.

Want me to pull the KEV required actions for the first two?

**User:** Yes, and show me the details on Log4Shell.

*Assistant calls `is_known_exploited` with `["CVE-2021-44228", "CVE-2024-3400"]` and `lookup_cve` with `CVE-2021-44228`, then summarizes the required actions, affected versions (2.0-beta9 through 2.15.0) and the CWE (CWE-917, expression-language injection).*

## Scoring formula

```
base  = 100 × (0.4 × CVSS/10 + 0.6 × EPSS)

score = 90 + base/10      if the CVE is in CISA KEV   → tier CRITICAL  (score 90-100)
score = base              otherwise                   → tier HIGH   if score ≥ 60
                                                        tier MEDIUM if score ≥ 35
                                                        tier LOW    if score < 35
```

Design choices:

- **KEV overrides everything.** It is evidence of exploitation, not a prediction, so a KEV-listed CVE always ranks above any non-KEV CVE, no matter how high its CVSS or EPSS. CRITICAL is reserved for KEV.
- **EPSS weighs more than CVSS (60/40).** Exploitation likelihood drives risk more than theoretical impact. A CVSS 10.0 with EPSS ≈ 0 lands at 40 (MEDIUM); a CVSS 6.0 with EPSS 0.9 lands at 78 (HIGH).
- **EPSS is used as a probability, not a percentile.** Percentiles inflate small scores (a 2% EPSS is often above the 80th percentile). Percentiles are shown for context only.
- **CVSS v3.1 is preferred** for scoring because nearly every CVE in NVD has one, so scores stay comparable across the list. v4.0 is used when v3.1 is missing, then v3.0, then v2. `lookup_cve` shows all of them.
- **Missing data is visible.** No CVSS yet → assume 5.0; no EPSS → 0. Both are called out in the rationale, as are unreachable sources.
- **Ties** break on EPSS, then CVSS, then CVE ID.

This is a triage aid, not a replacement for context. Asset exposure, compensating controls and business criticality still matter, which is exactly what the assistant can ask you about next.

## Reliability

- **Rate limits:** sliding-window pacing for NVD (5 or 50 requests / 30 s), plus exponential backoff with jitter on 403 / 429 / 5xx, honouring `Retry-After`.
- **Timeouts:** 20 s per request (45 s for the 1.8 MB KEV feed), with up to 3 retries.
- **Caching:** in-memory TTL cache. NVD and EPSS answers live for 6 h, the KEV catalog for 12 h. Concurrent KEV loads share one download.
- **Errors are tool results, not crashes:** upstream failures come back as MCP tool errors (`isError: true`) with a readable message. `prioritize_cves` degrades gracefully: if one source is down it still ranks with the others and says what was missing.
- **Input validation:** every argument is a zod schema; responses from all three APIs are validated before use.

## Development

```bash
npm test           # vitest, offline: recorded API fixtures in test/fixtures
npm run typecheck  # tsc over src, tests and scripts
npm run build      # compile to dist/
npm run dev        # run the server from source with tsx
npm run smoke      # live check against the real APIs (needs network)
```

```
src/
  index.ts            stdio entry point
  server.ts           builds the McpServer and wires the clients
  config.ts           endpoints, timeouts, TTLs, limits
  scoring.ts          priority formula, tiers, rationale
  prioritize.ts       fan-out to the three sources with graceful degradation
  format.ts           Markdown rendering of tool output
  types.ts            domain types
  lib/                http (timeout + backoff), TTL cache, rate limiter, CVE ID validation
  sources/            NVD, EPSS and KEV clients and response parsers
  tools/              one file per MCP tool
test/                 unit + in-memory MCP integration tests, recorded fixtures
scripts/smoke.ts      live smoke test
```

<details>
<summary><strong>Full <code>npm run smoke</code> output (2026-11-17)</strong></summary>

```
===== lookup_cve {"cve_id":"CVE-2021-44228","max_references":3} [ok, 585 ms]

## CVE-2021-44228
**Status:** Analyzed · **Published:** 2021-12-10 · **Last modified:** 2026-08-11

- **CVSS v3.1:** 10.0 CRITICAL — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (nvd@nist.gov, Primary)
- **CVSS v2.0:** 9.3 HIGH — `AV:N/AC:M/Au:N/C:C/I:C/A:C` (nvd@nist.gov, Primary)
- **CWE:** CWE-20, CWE-400, CWE-502, CWE-917

**Description:** Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

**References** (3 of 52):
- http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html — Third Party Advisory, VDB Entry
- http://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html — Third Party Advisory, VDB Entry
- http://packetstormsecurity.com/files/165261/Apache-Log4j2-2.14.1-Information-Disclosure.html — Exploit, Third Party Advisory, VDB Entry

Source: https://nvd.nist.gov/vuln/detail/CVE-2021-44228

===== epss_score {"cve_ids":["CVE-2021-44228"]} [ok, 119 ms]

| CVE | EPSS (30-day exploit probability) | Percentile | Model date |
|---|---|---|---|
| CVE-2021-44228 | 99.9% | p100.0 | 2026-11-16 |

EPSS = probability of exploitation activity in the next 30 days (FIRST.org). Percentile = share of all CVEs with a lower score.

===== is_known_exploited {"cve_ids":["CVE-2021-44228"]} [ok, 261 ms]

### CVE-2021-44228 — LISTED in CISA KEV
- **Name:** Apache Log4j2 Remote Code Execution Vulnerability
- **Vendor / product:** Apache / Log4j2
- **Date added:** 2021-12-10 · **Federal due date:** 2021-12-24
- **Known ransomware use:** Known
- **Required action:** For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available.
- **Summary:** Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.

Catalog version 2026.11.13 (1781 entries). Absence from KEV is not proof that a CVE is unexploited.

===== prioritize_cves {"cve_ids":["CVE-2023-38545","CVE-2024-45337","CVE-2021-44228","CVE-2024-24790","CVE-2024-3400"]} [ok, 570 ms]

| # | CVE | Tier | Score | KEV | EPSS | CVSS | Rationale |
|---|---|---|---|---|---|---|---|
| 1 | CVE-2021-44228 | CRITICAL | 100.0 | yes (ransomware) | 99.9% | 10.0 (v3.1) | Patch now — exploited in the wild: CISA KEV since 2021-12-10 (ransomware use), EPSS 99.9% (p100.0), CVSS 10.0 CRITICAL. |
| 2 | CVE-2024-3400 | CRITICAL | 100.0 | yes (ransomware) | 99.9% | 10.0 (v3.1) | Patch now — exploited in the wild: CISA KEV since 2024-04-12 (ransomware use), EPSS 99.9% (p100.0), CVSS 10.0 CRITICAL. |
| 3 | CVE-2023-38545 | HIGH | 86.2 | no | 78.3% | 9.8 (v3.1) | Patch soon — exploitation highly likely: not in KEV, EPSS 78.3% (p99.5), CVSS 9.8 CRITICAL. |
| 4 | CVE-2024-24790 | MEDIUM | 40.4 | no | 1.9% | 9.8 (v3.1) | Schedule — severe on paper, but low exploitation likelihood: not in KEV, EPSS 1.9% (p80.6), CVSS 9.8 CRITICAL. |
| 5 | CVE-2024-45337 | MEDIUM | 38.7 | no | 3.7% | 9.1 (v3.1) | Schedule — severe on paper, but low exploitation likelihood: not in KEV, EPSS 3.7% (p90.1), CVSS 9.1 CRITICAL. |

Score = 100 × (0.4 × CVSS/10 + 0.6 × EPSS). KEV-listed CVEs are lifted to 90 + base/10 and always rank CRITICAL. Non-KEV tiers: HIGH ≥ 60, MEDIUM ≥ 35, LOW < 35.

===== search_cves {"keyword":"log4j jndi","limit":3} [ok, 29100 ms]

Showing 3 of 7 NVD results for "log4j jndi":

| CVE | CVSS | Published | Summary |
|---|---|---|---|
| CVE-2021-44228 | 10.0 (v3.1) | 2021-12-10 | Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other… |
| CVE-2021-4104 | 7.5 (v3.1) | 2021-12-14 | JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName… |
| CVE-2021-45046 | 9.0 (v3.1) | 2021-12-14 | It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the… |

Refine the keywords or raise `limit` to see more.
```

The `search_cves` call took 29 s because it was the sixth NVD request in 30 s without an API key: the limiter waited instead of getting the client blocked.

</details>

## Data sources and terms

- NVD: *This product uses the NVD API but is not endorsed or certified by the NVD.*
- EPSS: FIRST.org, [Exploit Prediction Scoring System](https://www.first.org/epss/).
- KEV: CISA [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## License

[MIT](LICENSE) © Raül Silvero
