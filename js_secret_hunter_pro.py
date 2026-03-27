#!/usr/bin/env python3
"""
js_secret_hunter_pro.py

JavaScript secret scanner for bug bounty / pentest workflows.

Modes
-----
strict      : low-noise, high-confidence only
balanced    : adds safe heuristics
aggressive  : wider secret hunting, more noise

Features
--------
- local JS files or remote JS URLs from jsfiles.txt
- strict structural validation for:
  * JWT
  * Basic Auth
  * MongoDB URIs
  * credential-bearing URLs
  * private keys
- optional full-value output (--no-mask)
- optional JWT header/payload decoding in notes (--decode-jwt)
- optional noisy bundle scan (--allow-noisy-bundles)
- text + optional JSON report

Examples
--------
python3 js_secret_hunter_pro.py -i jsfiles.txt -o findings.txt --verbose
python3 js_secret_hunter_pro.py -i jsfiles.txt -o findings.txt --mode balanced --json findings.json
python3 js_secret_hunter_pro.py -i jsfiles.txt -o findings.txt --mode aggressive --allow-noisy-bundles --no-mask
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("[-] Missing dependency: requests. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)

USER_AGENT = "JS-Secret-Hunter-Pro/4.0"
MINIFIED_LINE_LEN = 1400


@dataclass
class Finding:
    file: str
    line: int
    category: str
    severity: str
    confidence: str
    matched: str
    context: str
    note: str = ""


# ---------------------------
# Strong low-noise patterns
# ---------------------------

NOISY_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:polyfills?|runtime|webpack|vendor|vendors|framework|frameworks|chunk-vendors|commons|bootstrap|react|next|nuxt|angular)(?:[-._].*)?\.js(?:$|\?)"
)
DOC_URL_RE = re.compile(
    r"(?i)(react\.dev|developer\.mozilla\.org|swagger|openapi|github\.com/.+/docs|/docs/|/errors/)"
)

PRIVATE_KEY_BEGIN_RE = re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")
PRIVATE_KEY_END_RE = re.compile(r"-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")

AWS_ACCESS_KEY_RE = re.compile(r"(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|ANPA|ANVA|AROA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
GOOGLE_API_KEY_RE = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,255}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{10,200}\b")
STRIPE_LIVE_RE = re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")
STRIPE_RK_RE = re.compile(r"\brk_live_[0-9A-Za-z]{16,}\b")

MONGODB_URI_RE = re.compile(r"\bmongodb(?:\+srv)?://[^\"\'\s]+")
CREDENTIAL_URL_RE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+\-.]*://[^/\s:@]+:[^/\s:@]+@[^\"\'\s)]+)")
S3_URL_RE = re.compile(
    r"\b(?:s3://[A-Za-z0-9.\-_]+(?:/[^\s\"\'`<>]*)?|https?://[A-Za-z0-9.\-_]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/[^\s\"\'`<>]*)?|https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/[A-Za-z0-9.\-_]+(?:/[^\s\"\'`<>]*)?)"
)
FIREBASE_URL_RE = re.compile(r"\bhttps://[A-Za-z0-9\-_]+\.firebaseio\.com(?:/[^\s\"\'`<>]*)?")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")
BASIC_AUTH_RE = re.compile(r"(?i)\bBasic\s+([A-Za-z0-9+/=]{16,})\b")

# ---------------------------
# Optional heuristics
# ---------------------------

GENERIC_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?:
        ["']?
        (?P<key>
            password|passwd|pwd|secret|clientsecret|client_secret|api[-_]?key|apikey|
            access[-_]?key|accesskey|auth[-_]?token|authtoken|token|bearer|jwt|
            private[-_]?key|privatekey|secret[-_]?key|secretkey|db[-_]?pass|database[-_]?password|
            aws[-_]?secret|aws[-_]?access[-_]?key|smtp[-_]?pass|ftp[-_]?pass
        )
        ["']?
        \s*[:=]\s*
        (?P<quote>["'])
        (?P<value>.*?)
        (?P=quote)
    )
    """
)

SENSITIVE_URL_RE = re.compile(
    r"""(?ix)\bhttps?://[^\s"'`<>]+(?:admin|internal|private|debug|staging|dev|prod|auth|token|oauth|signin|login|webhook|callback)[^\s"'`<>]*"""
)
STRING_LITERAL_RE = re.compile(r"""(["'])(?P<value>[^"']{8,})\1""")
STRONG_SECRET_NAME_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[-_]?key|apikey|auth[-_]?token|access[-_]?token|bearer|client_secret|private_key|db_pass)\b"
)
BASE64_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
WEAK_SECRET_RE = re.compile(
    r"""(?ix)\b(password|passwd|pwd|secret|token|api[-_]?key|apikey)\b\s*[:=]\s*["']?([^\s"',;}{]{4,})"""
)


def is_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://")


def read_targets(input_file: str) -> List[str]:
    targets: List[str] = []
    with open(input_file, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


def fetch_target(target: str, timeout: int) -> str:
    if is_url(target):
        resp = requests.get(target, timeout=timeout, headers={"User-Agent": USER_AGENT}, allow_redirects=True)
        resp.raise_for_status()
        return resp.text
    return Path(target).read_text(encoding="utf-8", errors="ignore")


def safe_snippet(text: str, limit: int = 180) -> str:
    clean = text.replace("\r", " ").replace("\n", " ").strip()
    return clean[:limit] + ("..." if len(clean) > limit else "")


def mask_secret(value: str, no_mask: bool, keep: int = 4) -> str:
    if no_mask:
        return value
    if len(value) <= keep * 2:
        return value
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def is_probably_minified(line: str) -> bool:
    return len(line) > MINIFIED_LINE_LEN and line.count(" ") < max(5, len(line) // 100)


def is_noisy_bundle(target: str) -> bool:
    return bool(NOISY_PATH_RE.search(target))


def b64url_decode_text(s: str) -> str:
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s.encode()).decode("utf-8", errors="ignore")


def jwt_decoded(value: str) -> Optional[Tuple[dict, dict]]:
    parts = value.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode_text(parts[0]))
        payload = json.loads(b64url_decode_text(parts[1]))
        if isinstance(header, dict) and isinstance(payload, dict):
            return header, payload
    except Exception:
        return None
    return None


def jwt_looks_real(value: str) -> bool:
    decoded = jwt_decoded(value)
    if not decoded:
        return False
    header, payload = decoded
    header_ok = bool({"alg", "typ"} & set(header.keys()))
    payload_ok = bool({"sub", "iss", "aud", "exp", "iat", "nbf"} & set(payload.keys()))
    return header_ok and payload_ok


def jwt_note(value: str, decode_jwt: bool) -> str:
    if not decode_jwt:
        return "JWT with decodable structured header/payload"
    decoded = jwt_decoded(value)
    if not decoded:
        return "JWT-like token"
    header, payload = decoded
    safe_payload = {k: payload.get(k) for k in ["sub", "iss", "aud", "exp", "iat", "nbf"] if k in payload}
    return f"JWT decoded | header_keys={sorted(header.keys())} | payload_fields={safe_payload}"


def decode_basic_auth_token(token: str) -> Optional[str]:
    try:
        raw = base64.b64decode(token + "=" * ((4 - len(token) % 4) % 4), validate=False)
        decoded = raw.decode("utf-8", errors="ignore")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    user, pwd = decoded.split(":", 1)
    if not user or not pwd:
        return None
    if len(user) > 128 or len(pwd) > 256:
        return None
    if not re.fullmatch(r"[\x20-\x7e]+", decoded):
        return None
    if re.fullmatch(r"[^A-Za-z0-9._@-]+", user):
        return None
    if re.fullmatch(r"[^A-Za-z0-9._@!$%*+=-]+", pwd):
        return None
    return decoded


def valid_hostname_or_ip(host: str) -> bool:
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return True
    if "." in host and re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return True
    return False


def credential_url_looks_real(value: str) -> bool:
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*://)([^:/\s@]+):([^/\s@]+)@([^\"\'\s/:]+)", value)
    if not m:
        return False
    user = m.group(2)
    pwd = m.group(3)
    host = m.group(4)
    combined = f"{user}:{pwd}:{host}".lower()
    if any(x in combined for x in [
        "mongo", "mongodb", "mysql", "postgres", "postgresql", "redis", "twilio",
        "base", "port", "hostname", "username", "password"
    ]):
        return False
    if host.lower() == "localhost":
        return False
    if not valid_hostname_or_ip(host):
        return False
    return True


def mongodb_uri_looks_real(value: str) -> bool:
    m = re.match(r"^mongodb(?:\+srv)?://([^\"\'\s]+)$", value)
    if not m:
        return False
    rest = m.group(1)
    if any(x in rest.lower() for x in ["hostname", "username", "password", "database", "port", "base"]):
        return False
    host_part = rest.split("/", 1)[0]
    if "@" in host_part:
        host_part = host_part.split("@", 1)[1]
    if ":" in host_part:
        host_part = host_part.split(":", 1)[0]
    return valid_hostname_or_ip(host_part)


def private_key_looks_real(content: str) -> bool:
    if not PRIVATE_KEY_BEGIN_RE.search(content):
        return False
    if not PRIVATE_KEY_END_RE.search(content):
        return False
    m = re.search(
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----([A-Za-z0-9+/=\r\n]{64,})-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        content,
        flags=re.DOTALL,
    )
    return bool(m)


def looks_like_secret_value(value: str) -> bool:
    if len(value) < 8:
        return False
    if value.lower() in {"true", "false", "null", "undefined", "none", "test", "example", "sample"}:
        return False
    if re.fullmatch(r"[0-9a-f]{6,8}", value, flags=re.I):
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,40}", value):
        return False
    if re.fullmatch(r"[A-Z][a-z]+(?:[A-Z][a-z]+){0,5}", value):
        return False
    if value.lower().endswith(("password", "token", "key")) and value[:1].isupper():
        return False
    return len(value) >= 16 or entropy(value) >= 3.8


def entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {c: data.count(c) for c in set(data)}
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def should_skip_file(target: str, lines: List[str], allow_noisy_bundles: bool) -> bool:
    if is_noisy_bundle(target) and not allow_noisy_bundles:
        return True
    if len(lines) <= 3 and any(is_probably_minified(line) for line in lines):
        return True
    return False


def line_cluster_noise(raw_hits: List[Tuple[str, str]]) -> bool:
    cats = {cat for cat, _ in raw_hits}
    return len(cats) >= 3


def add_finding(
    findings: List[Finding],
    target: str,
    line_no: int,
    category: str,
    severity: str,
    confidence: str,
    raw: str,
    context: str,
    note: str,
    no_mask: bool,
) -> None:
    findings.append(Finding(
        target,
        line_no,
        category,
        severity,
        confidence,
        mask_secret(raw, no_mask=no_mask),
        context,
        note,
    ))


def scan_content(
    target: str,
    content: str,
    max_lines: int,
    allow_noisy_bundles: bool,
    mode: str,
    no_mask: bool,
    decode_jwt: bool,
) -> List[Finding]:
    findings: List[Finding] = []
    lines = content.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines]

    if should_skip_file(target, lines, allow_noisy_bundles):
        return []

    has_real_private_key = private_key_looks_real(content)

    for line_no, line in enumerate(lines, start=1):
        context = safe_snippet(line)
        raw_hits: List[Tuple[str, str]] = []

        # Strong patterns
        for m in AWS_ACCESS_KEY_RE.finditer(line):
            raw_hits.append(("AWS Access Key ID", m.group(0)))
        for m in GOOGLE_API_KEY_RE.finditer(line):
            raw_hits.append(("Google API Key", m.group(0)))
        for m in GITHUB_TOKEN_RE.finditer(line):
            raw_hits.append(("GitHub Token", m.group(0)))
        for m in SLACK_TOKEN_RE.finditer(line):
            raw_hits.append(("Slack Token", m.group(0)))
        for m in STRIPE_LIVE_RE.finditer(line):
            raw_hits.append(("Stripe Live Key", m.group(0)))
        for m in STRIPE_RK_RE.finditer(line):
            raw_hits.append(("Stripe Restricted Live Key", m.group(0)))
        for m in MONGODB_URI_RE.finditer(line):
            raw_hits.append(("MongoDB URI", m.group(0)))
        for m in CREDENTIAL_URL_RE.finditer(line):
            raw_hits.append(("Credential in URL", m.group(1)))
        for m in S3_URL_RE.finditer(line):
            raw_hits.append(("S3 URL", m.group(0)))
        for m in FIREBASE_URL_RE.finditer(line):
            raw_hits.append(("Firebase URL", m.group(0)))
        for m in JWT_RE.finditer(line):
            raw_hits.append(("JWT", m.group(0)))
        for m in BASIC_AUTH_RE.finditer(line):
            raw_hits.append(("Basic Auth Literal", m.group(1)))

        pk_match = PRIVATE_KEY_BEGIN_RE.search(line)
        if pk_match:
            raw_hits.append(("Private Key Block", pk_match.group(0)))

        if line_cluster_noise(raw_hits) and is_probably_minified(line):
            raw_hits = []

        for category, raw in raw_hits:
            if category == "Private Key Block":
                if has_real_private_key:
                    add_finding(findings, target, line_no, category, "critical", "high", raw, context, "Private key material exposed", no_mask)
            elif category == "AWS Access Key ID":
                add_finding(findings, target, line_no, category, "high", "high", raw, context, "Possible AWS access key ID", no_mask)
            elif category == "Google API Key":
                add_finding(findings, target, line_no, category, "high", "high", raw, context, "Possible Google API key", no_mask)
            elif category == "GitHub Token":
                add_finding(findings, target, line_no, category, "high", "high", raw, context, "Possible GitHub token", no_mask)
            elif category == "Slack Token":
                add_finding(findings, target, line_no, category, "high", "high", raw, context, "Possible Slack token", no_mask)
            elif category == "Stripe Live Key":
                add_finding(findings, target, line_no, category, "high", "high", raw, context, "Possible Stripe live secret key", no_mask)
            elif category == "Stripe Restricted Live Key":
                add_finding(findings, target, line_no, category, "high", "high", raw, context, "Possible Stripe restricted live key", no_mask)
            elif category == "MongoDB URI":
                if mongodb_uri_looks_real(raw):
                    add_finding(findings, target, line_no, category, "high", "high", raw, context, "MongoDB connection string", no_mask)
            elif category == "Credential in URL":
                if credential_url_looks_real(raw):
                    add_finding(findings, target, line_no, category, "high", "high", raw, context, "Credential-bearing URL", no_mask)
            elif category == "S3 URL":
                if not DOC_URL_RE.search(raw):
                    add_finding(findings, target, line_no, category, "medium", "high", raw, context, "S3 bucket/path reference", no_mask)
            elif category == "Firebase URL":
                if not DOC_URL_RE.search(raw):
                    add_finding(findings, target, line_no, category, "medium", "high", raw, context, "Firebase endpoint reference", no_mask)
            elif category == "JWT":
                if jwt_looks_real(raw):
                    add_finding(findings, target, line_no, category, "medium", "high", raw, context, jwt_note(raw, decode_jwt), no_mask)
            elif category == "Basic Auth Literal":
                decoded = decode_basic_auth_token(raw)
                if decoded:
                    add_finding(findings, target, line_no, "Decoded Basic Auth", "critical", "high", decoded, context, "Base64-decoded Basic auth credential", no_mask)

        # balanced / aggressive only
        if mode in {"balanced", "aggressive"}:
            for m in GENERIC_ASSIGNMENT_RE.finditer(line):
                key = m.group("key")
                value = m.group("value")
                if looks_like_secret_value(value):
                    sev = "high" if any(x in key.lower() for x in ["password", "passwd", "secret", "private"]) else "medium"
                    conf = "high" if len(value) >= 24 else "medium"
                    add_finding(findings, target, line_no, "Generic Secret Assignment", sev, conf, f"{key}={value}", context, "Potential hardcoded secret in variable/property assignment", no_mask)

            for m in SENSITIVE_URL_RE.finditer(line):
                raw = m.group(0)
                if not DOC_URL_RE.search(raw):
                    add_finding(findings, target, line_no, "Sensitive URL Pattern", "medium", "low", raw, context, "Interesting environment/admin/auth/debug URL in JS", no_mask)

        if mode == "aggressive":
            if STRONG_SECRET_NAME_RE.search(line):
                for sm in STRING_LITERAL_RE.finditer(line):
                    value = sm.group("value")
                    if len(value) >= 24 and entropy(value) >= 4.2 and looks_like_secret_value(value):
                        add_finding(findings, target, line_no, "High-Entropy Secret Candidate", "medium", "low", value, context, "High-entropy string next to strong secret variable name", no_mask)

            for m in BASE64_CANDIDATE_RE.finditer(line):
                token = m.group(0)
                decoded = decode_basic_auth_token(token)
                if decoded:
                    add_finding(findings, target, line_no, "Decoded Basic Auth", "critical", "high", decoded, context, "Standalone base64 token decodes to user:password", no_mask)

            for m in WEAK_SECRET_RE.finditer(line):
                key, value = m.group(1), m.group(2)
                if looks_like_secret_value(value):
                    add_finding(findings, target, line_no, "Weak Secret Pattern", "low", "low", f"{key}={value}", context, "Weak keyword-based secret pattern", no_mask)

    return deduplicate_findings(findings)


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out: List[Finding] = []
    for f in findings:
        key = (f.file, f.line, f.category, f.matched, f.context)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda x: (
        severity_order.get(x.severity, 9),
        confidence_order.get(x.confidence, 9),
        x.file,
        x.line,
        x.category,
    ))
    return out


def write_text_report(findings: List[Finding], output_file: str) -> None:
    severity_count: Dict[str, int] = {}
    category_count: Dict[str, int] = {}
    for f in findings:
        severity_count[f.severity] = severity_count.get(f.severity, 0) + 1
        category_count[f.category] = category_count.get(f.category, 0) + 1

    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write("JS Secret Hunter Pro Report\n")
        fh.write("=" * 90 + "\n\n")
        fh.write(f"Total findings: {len(findings)}\n")
        fh.write("By severity:\n")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_count:
                fh.write(f"  - {sev}: {severity_count[sev]}\n")
        fh.write("By category:\n")
        for category, count in sorted(category_count.items(), key=lambda x: (-x[1], x[0])):
            fh.write(f"  - {category}: {count}\n")
        fh.write("\nDetailed Findings\n")
        fh.write("-" * 90 + "\n\n")
        for idx, f in enumerate(findings, start=1):
            fh.write(f"[{idx}] {f.category} | {f.severity.upper()} | confidence={f.confidence}\n")
            fh.write(f"File    : {f.file}\n")
            fh.write(f"Line    : {f.line}\n")
            fh.write(f"Match   : {f.matched}\n")
            fh.write(f"Context : {f.context}\n")
            if f.note:
                fh.write(f"Note    : {f.note}\n")
            fh.write("\n")


def write_json_report(findings: List[Finding], output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="JavaScript secret scanner with strict, balanced, and aggressive modes.")
    parser.add_argument("-i", "--input", required=True, help="Text file containing JS URLs/paths, one per line.")
    parser.add_argument("-o", "--output", required=True, help="Text report output file.")
    parser.add_argument("--json", dest="json_output", help="Optional JSON report output file.")
    parser.add_argument("--timeout", type=int, default=12, help="HTTP timeout in seconds.")
    parser.add_argument("--max-lines", type=int, default=50000, help="Maximum lines to scan per file.")
    parser.add_argument("--allow-noisy-bundles", action="store_true", help="Also scan noisy vendor/runtime/polyfill bundles.")
    parser.add_argument("--mode", choices=["strict", "balanced", "aggressive"], default="strict", help="Scan mode.")
    parser.add_argument("--no-mask", action="store_true", help="Disable masking of secrets in output.")
    parser.add_argument("--decode-jwt", action="store_true", help="Add decoded JWT header/payload summary in notes.")
    parser.add_argument("--verbose", action="store_true", help="Print progress to stdout.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    targets = read_targets(args.input)
    if not targets:
        print("[-] No targets found in input file.", file=sys.stderr)
        sys.exit(1)

    all_findings: List[Finding] = []
    failures: List[Tuple[str, str]] = []

    for target in targets:
        try:
            if args.verbose:
                print(f"[+] Scanning: {target}")
            content = fetch_target(target, timeout=args.timeout)
            findings = scan_content(
                target=target,
                content=content,
                max_lines=args.max_lines,
                allow_noisy_bundles=args.allow_noisy_bundles,
                mode=args.mode,
                no_mask=args.no_mask,
                decode_jwt=args.decode_jwt,
            )
            all_findings.extend(findings)
        except Exception as exc:
            failures.append((target, str(exc)))
            if args.verbose:
                print(f"[-] Failed: {target} -> {exc}", file=sys.stderr)

    all_findings = deduplicate_findings(all_findings)
    write_text_report(all_findings, args.output)
    if args.json_output:
        write_json_report(all_findings, args.json_output)

    if failures:
        fail_file = args.output + ".errors.txt"
        with open(fail_file, "w", encoding="utf-8") as fh:
            for target, err in failures:
                fh.write(f"{target}\t{err}\n")
        print(f"[!] Some targets failed. See: {fail_file}")

    print(f"[+] Scan complete. Findings: {len(all_findings)}")
    print(f"[+] Text report written to: {args.output}")
    if args.json_output:
        print(f"[+] JSON report written to: {args.json_output}")


if __name__ == "__main__":
    main()