# Log4Shell (CVE-2021-44228) Security Notes

## Summary

**Log4Shell** is a critical remote code execution (RCE) vulnerability in Apache Log4j 2, an object-oriented Java logging framework. It exploits JNDI (Java Naming and Directory Interface) features in `log4j-core`. An attacker who can control log messages or log message parameters can trick Log4j into loading and executing arbitrary code from an attacker-controlled LDAP/RMI server, resulting in remote code execution.

## CVE Identifier

- **CVE-2021-44228** — JNDI lookup can be exploited to execute arbitrary code loaded from an LDAP server

## Affected Versions

Affected Log4j 2 versions (per Apache):

- `[2.0-beta9, 2.3.1)` ∪ `[2.4, 2.12.2)` ∪ `[2.13.0, 2.15.0)`
- In practical terms: **2.0-beta9 through 2.14.1**

Only the `log4j-core` JAR is impacted. Applications using only `log4j-api` without `log4j-core` are not affected.

## Fixed Versions

- **2.3.1** (Java 6)
- **2.12.2** (Java 7)
- **2.15.0** (Java 8 and later) — first version with the fix; JNDI LDAP lookups restricted to localhost by default
- **2.16.0** (Java 8+) / **2.12.3** (Java 7) / **2.3.1** (Java 6) — complete fix; JNDI lookup functionality removed
- Later security releases: **2.17.1** (Java 8+), **2.12.4** (Java 7), **2.3.2** (Java 6) — also address follow-on CVEs (CVE-2021-45046, CVE-2021-45105, CVE-2021-44832)

## Severity

- **CVSS 3.1 Base Score: 10.0 — CRITICAL**
- CVSS Vector: `(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)`
- EPSS: 94% (percentile 100%)
- CISA KEV: yes (added December 10, 2021)
- Note: Apache’s security page lists CVSS 9.0 CRITICAL (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H) for the incomplete-fix variant in non-default configurations; the canonical NVD/Rapid7 score is 10.0 CRITICAL.

## Remediation Actions

1. **Upgrade path:** Move to a fixed version — 2.15.0+ (Java 8+), 2.12.2+ (Java 7), 2.3.1+ (Java 6); prefer 2.16.0+/2.17.1+ where the JNDI lookup functionality is completely removed.
2. **Detect vulnerable deployments:** Inventory `log4j-core` versions across the estate; scan build artifacts, container images, and dependency manifests; search logs for `${jndi:...}` patterns and MDC/Thread Context Map injection patterns (e.g., `${ctx:loginId}`).
3. **Hardening:** Set `log4j2.formatMsgNoLookups=true` (temporary measure; does NOT fully mitigate the 2.15.0 incomplete fix in non-default configurations); remove the `JndiLookup` class from `log4j-core`; restrict outbound LDAP/RMI/DNS egress from application servers.
4. **Automated dependency scanning:** Integrate OWASP Dependency-Check, GitHub Dependabot, Trivy/Grype/Snyk into CI/CD; treat CVE-2021-44228 (CVSS 10.0) and follow-on CVEs as blocking; generate SBOMs per build.

## Sources

- Apache Logging Services Security Page: https://logging.apache.org/security.html
- NVD CVE-2021-44228: https://nvd.nist.gov/vuln/detail/cve-2021-44228
- Rapid7 Vulnerability Database: https://www.rapid7.com/db/vulnerabilities/cve-2021-44228/
- Oracle Security Alert (risk matrix): https://www.oracle.com/security-alerts/cve-2021-44228verbose.html
- JPCERT/CC Alert: https://www.jpcert.or.jp/english/at/2021/at210050.html
- Apache Log4j CVEs (ASF Blog): https://news.apache.org/foundation/entry/apache-log4j-cves
- Ubuntu Security Note: https://ubuntu.com/security/CVE-2021-44228
