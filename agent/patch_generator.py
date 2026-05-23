"""
Patch Generator
───────────────
Generates realistic, security-hardened file patches for each known CVE
or web-app vuln in vuln_catalog.ndjson.

  - CVE-* ids: pulled from the hardcoded CVE_PATCH_SPECS dict below
                (infrastructure-level config patches).
  - VULN-* ids: looked up in vuln_catalog.ndjson; the patch replaces the
                vulnerable file_path with the hardened content of the
                catalog's reference_patch_file (DVWA-style impossible.php).
  - Unknown id: generic requirements.txt bump (defensive fallback).

Returns list of {path, content, commit_message?} dicts ready to be committed
to a GitHub branch by agent/tools.py::create_patch_pr.
"""

import json
import os
from typing import Optional

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CATALOG_PATH = os.path.join(_REPO_ROOT, "vuln_catalog.ndjson")
_VULN_CATALOG_CACHE: dict[str, dict] | None = None


def _load_catalog_row(vuln_id: str) -> Optional[dict]:
    """Return the vuln_catalog.ndjson row for vuln_id, or None if not found."""
    global _VULN_CATALOG_CACHE
    if _VULN_CATALOG_CACHE is None:
        _VULN_CATALOG_CACHE = {}
        try:
            with open(_CATALOG_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    row = json.loads(line)
                    if row.get("vuln_id"):
                        _VULN_CATALOG_CACHE[row["vuln_id"]] = row
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[patch_generator] could not load catalog: {e}")
    return _VULN_CATALOG_CACHE.get(vuln_id)


CVE_PATCH_SPECS: dict[str, dict] = {

    # ── CVE-2024-6387 ─ OpenSSH regreSSHion (RCE, CVSS 9.8) ──────────────────
    "CVE-2024-6387": {
        "package": "openssh-server",
        "affected": "9.2p1",
        "fixed": "9.8p1",
        "files": [
            {
                "path": "infrastructure/Dockerfile",
                "content": """\
FROM ubuntu:22.04

# CVE-2024-6387 (regreSSHion): upgrade openssh-server from 9.2p1 to 9.8p1
# Fixes unauthenticated RCE via signal handler race condition (CVSS 9.8)
RUN apt-get update && apt-get install -y --no-install-recommends \\
        openssh-server=1:9.8p1-1 \\
    && apt-mark hold openssh-server \\
    && rm -rf /var/lib/apt/lists/*

# Verify the installed version is safe before continuing
RUN dpkg -l openssh-server | awk '/openssh-server/{print $3}' | grep -q "9.8p1" \\
    || (echo "ERROR: openssh-server version check failed — aborting build" && exit 1)

COPY infrastructure/sshd_config /etc/ssh/sshd_config

RUN mkdir -p /run/sshd
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
""",
            },
            {
                "path": "infrastructure/sshd_config",
                "content": """\
# Hardened sshd_config — CVE-2024-6387 (regreSSHion) remediation
# Ref: https://nvd.nist.gov/vuln/detail/CVE-2024-6387
# Ref: https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt

Protocol 2

# Disable unauthenticated attack vectors
PermitEmptyPasswords no
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no

# Limit the window a race condition can be exploited
LoginGraceTime 20
MaxStartups 10:30:60
MaxAuthTries 3
MaxSessions 5

# Restrict to known-good client IPs (internal VPN + bastion)
AllowUsers deploy@10.0.0.0/8

# Modern crypto only
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com

# Logging for audit trail
LogLevel VERBOSE
SyslogFacility AUTH
""",
            },
        ],
    },

    # ── CVE-2023-44487 ─ HTTP/2 Rapid Reset (DoS, CVSS 7.5) ──────────────────
    "CVE-2023-44487": {
        "package": "nginx",
        "affected": "1.24.0",
        "fixed": "1.25.3",
        "files": [
            {
                "path": "infrastructure/Dockerfile.nginx",
                "content": """\
# CVE-2023-44487 (HTTP/2 Rapid Reset): upgrade nginx from 1.24.0 to 1.25.3
# Fixes remote DoS via crafted HTTP/2 RST_STREAM frames (CVSS 7.5)
# Ref: https://nvd.nist.gov/vuln/detail/CVE-2023-44487
FROM nginx:1.25.3-alpine

# Verify version
RUN nginx -v 2>&1 | grep -q "1.25.3" \\
    || (echo "ERROR: nginx version check failed" && exit 1)

COPY infrastructure/nginx.conf /etc/nginx/nginx.conf

EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]
""",
            },
            {
                "path": "infrastructure/nginx.conf",
                "content": """\
# nginx.conf — CVE-2023-44487 (HTTP/2 Rapid Reset) hardened config
# Ref: https://nvd.nist.gov/vuln/detail/CVE-2023-44487
# Defense-in-depth: HTTP/2 disabled + rate limiting applied

worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # Rate limiting — prevent resource exhaustion attacks
    limit_req_zone $binary_remote_addr zone=global:10m rate=100r/m;
    limit_conn_zone $binary_remote_addr zone=addr:10m;

    server {
        listen 80;
        # HTTP/2 intentionally omitted — disabled to prevent Rapid Reset Attack
        listen 443 ssl;

        ssl_certificate     /etc/ssl/certs/server.crt;
        ssl_certificate_key /etc/ssl/private/server.key;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

        limit_req  zone=global burst=20 nodelay;
        limit_conn addr 20;

        location / {
            proxy_pass         http://backend:8080;
            proxy_http_version 1.1;
            proxy_set_header   Host $host;
            proxy_set_header   X-Real-IP $remote_addr;
        }
    }
}
""",
            },
        ],
    },

    # ── CVE-2021-44228 ─ Log4Shell (RCE, CVSS 10.0) ───────────────────────────
    "CVE-2021-44228": {
        "package": "log4j-core",
        "affected": "2.14.1",
        "fixed": "2.15.0",
        "files": [
            {
                "path": "app/pom.xml",
                "content": """\
<?xml version="1.0" encoding="UTF-8"?>
<!-- CVE-2021-44228 (Log4Shell): upgraded log4j-core from 2.14.1 to 2.15.0 -->
<!-- Fixes unauthenticated RCE via JNDI injection in log messages (CVSS 10.0) -->
<!-- Ref: https://nvd.nist.gov/vuln/detail/CVE-2021-44228 -->
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>

    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.15.0</version>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-api</artifactId>
            <version>2.15.0</version>
        </dependency>
    </dependencies>
</project>
""",
            },
            {
                "path": "infrastructure/Dockerfile.app",
                "content": """\
FROM openjdk:17-slim

# CVE-2021-44228 (Log4Shell): defense-in-depth — env var + JVM flag + upgraded jar
# Ref: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
# Ref: https://logging.apache.org/log4j/2.x/security.html

WORKDIR /app

# Defense layer 1: environment variable disables JNDI lookups at the JVM level
ENV LOG4J_FORMAT_MSG_NO_LOOKUPS=true
ENV LOG4J2_FORMATMSGNOOOKUPS=true

COPY target/app-1.0.0.jar app.jar

# Verify log4j version inside the jar is not the vulnerable 2.14.1
RUN jar tf app.jar | grep -i "log4j-core" | grep -v "2.14.1" \\
    || (echo "ERROR: vulnerable log4j version detected in jar" && exit 1)

EXPOSE 8080
# Defense layer 2: JVM flag as additional mitigation
CMD ["java", \\
     "-Dlog4j2.formatMsgNoLookups=true", \\
     "-Dlog4j2.disable.jmx=true", \\
     "-jar", "app.jar"]
""",
            },
        ],
    },

    # ── CVE-2024-3094 ─ XZ Utils backdoor (Supply Chain, CVSS 9.0) ────────────
    "CVE-2024-3094": {
        "package": "xz-utils",
        "affected": "5.6.0",
        "fixed": "5.4.6",
        "files": [
            {
                "path": "infrastructure/Dockerfile",
                "content": """\
FROM debian:bookworm-slim

# CVE-2024-3094 (XZ Utils backdoor): downgrade from 5.6.0 to 5.4.6
# The 5.6.x branch contains a supply-chain backdoor in liblzma that
# allows unauthorized SSH access via a malicious sshd hook (CVSS 9.0)
# Ref: https://nvd.nist.gov/vuln/detail/CVE-2024-3094
# Ref: https://www.openwall.com/lists/oss-security/2024/03/29/4

RUN apt-get update && apt-get install -y --no-install-recommends \\
        xz-utils=5.4.1-0.2 \\
    && apt-mark hold xz-utils \\
    && rm -rf /var/lib/apt/lists/*

# Verify binary is not the backdoored version
RUN xz --version | head -1 | grep -qE "5\\.4\\." \\
    || (echo "ERROR: xz-utils version check failed — 5.6.x detected" && exit 1)

COPY infrastructure/verify_xz.sh /usr/local/bin/verify_xz.sh
RUN chmod +x /usr/local/bin/verify_xz.sh && /usr/local/bin/verify_xz.sh

WORKDIR /app
COPY . .
CMD ["./entrypoint.sh"]
""",
            },
            {
                "path": "infrastructure/verify_xz.sh",
                "content": """\
#!/usr/bin/env bash
# CVE-2024-3094: verify xz-utils is not the backdoored 5.6.x series
# Run at image build time AND as part of startup health check
set -euo pipefail

XZ_VERSION=$(xz --version | head -1 | awk '{print $NF}')
BACKDOORED_VERSIONS=("5.6.0" "5.6.1")

for BAD in "${BACKDOORED_VERSIONS[@]}"; do
    if [[ "${XZ_VERSION}" == "${BAD}" ]]; then
        echo "[verify_xz] CRITICAL: xz-utils ${XZ_VERSION} is BACKDOORED (CVE-2024-3094)"
        echo "[verify_xz] Downgrade to 5.4.6 immediately: apt-get install xz-utils=5.4.1-0.2"
        exit 1
    fi
done

echo "[verify_xz] OK: xz-utils ${XZ_VERSION} is safe (not in backdoored 5.6.x series)"
""",
            },
        ],
    },

    # ── CVE-2023-23397 ─ Outlook NTLM hash leak (Credential, CVSS 6.5) ────────
    "CVE-2023-23397": {
        "package": "libmapi",
        "affected": "4.17.0",
        "fixed": "4.18.0",
        "files": [
            {
                "path": "infrastructure/requirements.txt",
                "content": """\
# CVE-2023-23397 (Outlook NTLM hash leak via UNC path): upgraded from 4.17.0 to 4.18.0
# Fixes NTLM credential capture via crafted calendar reminder notification (CVSS 6.5)
# Ref: https://nvd.nist.gov/vuln/detail/CVE-2023-23397
# Ref: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397
samba==4.18.0
libmapi==4.18.0
python-samba==4.18.0
""",
            },
            {
                "path": "infrastructure/smb.conf",
                "content": """\
# smb.conf — CVE-2023-23397 (NTLM hash capture) hardened config
# Defense-in-depth: disable NTLM auth + block outbound SMB UNC path resolution
# Ref: https://nvd.nist.gov/vuln/detail/CVE-2023-23397

[global]
    workgroup = WORKGROUP
    security  = user

    # Disable NTLM authentication — prevents hash capture via UNC path
    ntlm auth          = no
    lanman auth        = no
    lm announce        = no

    # Restrict anonymous access
    restrict anonymous = 2
    map to guest       = never

    # Modern SMB only — disable legacy protocols used in relay attacks
    client min protocol = SMB3
    server min protocol = SMB3

    # Block outbound connections that could be used to steal NTLM hashes
    # (Firewall rule: block TCP 445 outbound must also be applied at host level)
    bind interfaces only = yes
    interfaces = lo eth0
""",
            },
        ],
    },
}


def generate_patches(cve_id: str, cve_data: Optional[dict] = None) -> list[dict]:
    """
    Returns list of {path, content[, commit_message]} dicts for the given vuln.

      VULN-*   : catalog-driven — replaces vulnerable file_path with the
                 hardened reference_patch_file content.
      CVE-*    : looked up in CVE_PATCH_SPECS (hardcoded infra patches).
      unknown  : generic requirements.txt bump.
    """
    # ── VULN-* catalog entries (DVWA-style web-app vulns) ───────────────────
    if cve_id.startswith("VULN-"):
        row = _load_catalog_row(cve_id)
        if row:
            ref_path = row.get("reference_patch_file") or ""
            dst_path = row.get("file_path") or ""
            ref_abs  = os.path.join(_REPO_ROOT, ref_path)
            if ref_path and dst_path and os.path.exists(ref_abs):
                with open(ref_abs, "r", encoding="utf-8") as f:
                    content = f.read()
                return [{
                    "path":           dst_path,
                    "content":        content,
                    "commit_message": (
                        f"Fix {cve_id}: {row.get('name', 'security fix')} "
                        f"({row.get('cwe', '')})"
                    ),
                }]
            print(
                f"[patch_generator] {cve_id}: reference file not found at "
                f"{ref_abs} — using generic fallback"
            )

    # ── Known CVE-* infrastructure patches ──────────────────────────────────
    spec = CVE_PATCH_SPECS.get(cve_id)
    if spec:
        return spec["files"]

    # ── Generic fallback ────────────────────────────────────────────────────
    if cve_data:
        pkg = cve_data.get("package_name", "unknown-package")
        fixed = cve_data.get("fixed_version", "latest")
        affected = cve_data.get("affected_version", "unknown")
        return [
            {
                "path": "infrastructure/requirements.txt",
                "content": (
                    f"# {cve_id}: upgraded {pkg} from {affected} to {fixed}\n"
                    f"# Ref: https://nvd.nist.gov/vuln/detail/{cve_id}\n"
                    f"{pkg}=={fixed}\n"
                ),
            }
        ]

    return []
