#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         IPsec / IKEv2 PCAP Security Analyzer                ║
║         Rates captured VPN tunnel negotiations 0-100        ║
╚══════════════════════════════════════════════════════════════╝
Usage:
    python3 analyzer.py <file.pcap>
    python3 analyzer.py captures/
    python3 analyzer.py strong.pcap medium.pcap weak.pcap
"""

import sys
import re
import subprocess
import argparse
import os
from pathlib import Path
from typing import List, Dict, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Algorithm Knowledge Base
# pattern -> (display_name, severity, explanation)
# ─────────────────────────────────────────────────────────────────────────────
ALGORITHM_DB: Dict[str, Tuple[str, str, str]] = {
    # ── CRITICAL ──────────────────────────────────────────────────────────────
    r"\b3DES\b|ENCR_3DES|3des_cbc|triple.?des": (
        "3DES (Triple-DES)",
        "CRITICAL",
        "Export-era cipher. 112-bit effective key. SWEET32 attack exploitable in <2^32 blocks. Forbidden by NIST SP 800-131A."
    ),
    r"\bMD5\b|hmac_md5|auth_hmac_md5|AUTH_HMAC_MD5|PRF_HMAC_MD5": (
        "MD5",
        "CRITICAL",
        "Cryptographically broken. Collision attacks proven (Wang et al. 2004). Never use for authentication."
    ),
    r"MODP_1024|modp1024|Alternate 1024-bit MODP|DH.*Group.*\b2\b|1024.bit.*DH": (
        "MODP-1024 / DH Group 2",
        "CRITICAL",
        "Logjam attack (2015) proves NSA-level precomputation can break this. Passive decryption of recorded sessions is feasible."
    ),
    r"\bDES\b(?!-EDE)|des_cbc(?!_3)": (
        "Single DES",
        "CRITICAL",
        "56-bit key. Brute-forced in under 24h since 1999 (DES Cracker). Completely obsolete."
    ),
    r"NULL.*encr|encr.*NULL": (
        "NULL Encryption",
        "CRITICAL",
        "No encryption. Entire payload in plaintext. Catastrophic for VPN use."
    ),
    r"\bRC4\b|arcfour": (
        "RC4",
        "CRITICAL",
        "Biased keystream. Multiple practical attacks (RC4 NOMORE). Prohibited by RFC 7465."
    ),

    # ── MODERATE ──────────────────────────────────────────────────────────────
    r"AES_CBC_128|aes128.*cbc|aes.*128.*cbc|AES-CBC\s*\(128\)": (
        "AES-CBC-128",
        "MODERATE",
        "AES-128 key length is acceptable but CBC mode lacks AEAD. Padding oracle attacks possible if implemented incorrectly."
    ),
    r"\bSHA1\b|SHA_1|hmac_sha1|auth_hmac_sha1|SHA-1(?!96)|SHA1-96": (
        "SHA-1 / HMAC-SHA-1",
        "MODERATE",
        "SHAttered attack (2017) demonstrated first real SHA-1 collision. NIST deprecated since 2011."
    ),
    r"MODP_2048|modp2048|DH.*Group.*14|2048.bit.*DH": (
        "MODP-2048 / DH Group 14",
        "MODERATE",
        "Minimum NIST recommendation. Classical security only — not quantum-safe. Borderline acceptable for near-term use."
    ),
    r"AES_CBC_256|aes256.*cbc|aes.*256.*cbc|AES-CBC\s*\(256\)": (
        "AES-256-CBC",
        "MODERATE",
        "Strong key length but CBC mode has no built-in integrity. Prefer AES-GCM for authenticated encryption."
    ),

    # ── STRONG ────────────────────────────────────────────────────────────────
    r"AES_GCM_256|aes256gcm|aes.*256.*gcm|gcm.*256|AES-GCM\s*\(256\)": (
        "AES-256-GCM",
        "STRONG",
        "AEAD cipher. Authenticated encryption — no separate HMAC needed. NSA Suite B. Current gold standard."
    ),
    r"AES_GCM_128|aes128gcm|aes.*128.*gcm|gcm.*128|AES-GCM\s*\(128\)": (
        "AES-128-GCM",
        "STRONG",
        "AEAD cipher. 128-bit key. Efficient on AES-NI hardware. Widely deployed in modern TLS/IPsec."
    ),
    r"\bSHA2_384\b|SHA_384|hmac_sha2_384|sha384|SHA-384": (
        "SHA-384 / HMAC-SHA-384",
        "STRONG",
        "NSA Suite B. 192-bit security level. Excellent integrity algorithm."
    ),
    r"\bSHA2_256\b|SHA_256|hmac_sha2_256|sha256|SHA-256": (
        "SHA-256 / HMAC-SHA-256",
        "STRONG",
        "NIST approved. 128-bit collision resistance. Well-audited and widely deployed."
    ),
    r"\bSHA2_512\b|SHA_512|sha512|SHA-512": (
        "SHA-512",
        "STRONG",
        "256-bit collision resistance. Very strong integrity function."
    ),
    r"MODP_3072|modp3072|DH.*Group.*15|3072.bit": (
        "MODP-3072 / DH Group 15",
        "STRONG",
        "128-bit classical security equivalent. BSI and NIST approved for long-term use."
    ),
    r"MODP_4096|modp4096|DH.*Group.*16|4096.bit": (
        "MODP-4096 / DH Group 16",
        "STRONG",
        "Very strong classical DH. Suitable for high-security environments."
    ),
    r"ECP_256|P-256|ecp256|DH.*Group.*19": (
        "ECDH P-256 (ECP-256)",
        "STRONG",
        "Elliptic curve DH. 128-bit classical security. Efficient and NSA Suite B approved."
    ),
    r"ECP_384|P-384|ecp384|DH.*Group.*20": (
        "ECDH P-384 (ECP-384)",
        "STRONG",
        "Elliptic curve DH. 192-bit security. NSA Suite B top tier."
    ),
}

# Penalty per severity level
PENALTY = {"CRITICAL": 35, "MODERATE": 15, "STRONG": 0}

def grade(score: int) -> Tuple[str, str]:
    if score >= 90: return "A", "STRONG"
    if score >= 75: return "B", "ACCEPTABLE"
    if score >= 55: return "C", "WEAK"
    if score >= 35: return "D", "VULNERABLE"
    return "F", "CRITICAL RISK"

# ANSI color codes
C = {
    "CRITICAL": "\033[91m",
    "MODERATE": "\033[93m",
    "STRONG":   "\033[92m",
    "INFO":     "\033[96m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "RESET":    "\033[0m",
}

def col(text: str, key: str) -> str:
    return f"{C.get(key,'')}{text}{C['RESET']}"

SEP = "─" * 66

# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────

def extract_isakmp_text(pcap_path: str) -> str:
    """Dump verbose tshark output filtered to ISAKMP/IKEv2 packets."""
    try:
        r = subprocess.run(
            ["tshark", "-r", pcap_path, "-Y", "isakmp", "-V"],
            capture_output=True, text=True, timeout=45
        )
        return r.stdout
    except FileNotFoundError:
        print(col("[ERROR] tshark not found. Install: sudo apt install tshark", "CRITICAL"))
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(col(f"[ERROR] tshark timed out on {pcap_path}", "CRITICAL"))
        return ""

def detect_algorithms(raw: str) -> List[Dict]:
    found, seen = [], set()
    for pattern, (name, severity, explanation) in ALGORITHM_DB.items():
        if re.search(pattern, raw, re.IGNORECASE) and name not in seen:
            seen.add(name)
            found.append({"name": name, "severity": severity, "explanation": explanation})
    return found

def detect_ike_version(raw: str) -> str:
    if re.search(r"IKE version 2|IKEv2|ikev2", raw, re.IGNORECASE): return "IKEv2"
    if re.search(r"IKE version 1|IKEv1", raw, re.IGNORECASE):        return "IKEv1 (legacy)"
    return "Unknown"

def detect_auth_mode(raw: str) -> str:
    if re.search(r"pre.shared.key|PSK|AUTH_METHOD.*PSK", raw, re.IGNORECASE): return "PSK (Pre-Shared Key)"
    if re.search(r"RSA.*Sig|Digital.*Sig|certificate", raw, re.IGNORECASE):   return "RSA / Certificate"
    if re.search(r"\bEAP\b", raw, re.IGNORECASE):                             return "EAP"
    return "Unknown"

def packet_summary(raw: str) -> Dict[str, int]:
    types = {
        "IKE_SA_INIT":     r"IKE_SA_INIT",
        "IKE_AUTH":        r"IKE_AUTH",
        "CREATE_CHILD_SA": r"CREATE_CHILD_SA",
        "INFORMATIONAL":   r"INFORMATIONAL",
        "ESP":             r"Encapsulating Security Payload",
    }
    return {k: len(re.findall(v, raw, re.IGNORECASE)) for k, v in types.items()}

def compute_score(findings: List[Dict]) -> int:
    return max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))

# ─────────────────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────────────────

def wrap(text: str, width: int = 60, indent: str = "             ") -> List[str]:
    lines, line = [], indent
    for word in text.split():
        if len(line) + len(word) > width:
            lines.append(line.rstrip())
            line = indent + word + " "
        else:
            line += word + " "
    if line.strip():
        lines.append(line.rstrip())
    return lines

def score_color(score: int) -> str:
    if score >= 75: return "STRONG"
    if score >= 55: return "MODERATE"
    return "CRITICAL"

def print_report(pcap: str, findings, ike_ver, auth, pkts, score):
    letter, label = grade(score)
    sc = score_color(score)

    print(f"\n{col(SEP,'INFO')}")
    print(col(f"  FILE  : {os.path.basename(pcap)}", "BOLD"))
    print(col(f"  PATH  : {pcap}", "DIM"))
    print(col(SEP, "INFO"))

    print(f"\n  {col('IKE Version :', 'BOLD')} {ike_ver}")
    print(f"  {col('Auth Mode   :', 'BOLD')} {auth}")

    visible_pkts = {k: v for k, v in pkts.items() if v > 0}
    if visible_pkts:
        print(f"\n  {col('Packet Summary:', 'BOLD')}")
        for ptype, count in visible_pkts.items():
            print(f"    {ptype:<22} {count} pkt(s)")

    print(f"\n  {col('Algorithm Findings:', 'BOLD')}")
    if not findings:
        print(col("    No known algorithms detected. Check if pcap has IKE handshake.", "DIM"))
    else:
        severity_order = {"CRITICAL": 0, "MODERATE": 1, "STRONG": 2}
        for f in sorted(findings, key=lambda x: severity_order[x["severity"]]):
            badge = col(f"[{f['severity']:<8}]", f["severity"])
            name  = col(f["name"], f["severity"])
            print(f"\n    {badge} {name}")
            for line in wrap(f["explanation"]):
                print(col(f"    {line}", "DIM"))

    # Score bar
    filled = int(score / 2)
    bar = col("█" * filled, sc) + col("░" * (50 - filled), "DIM")
    print(f"\n  {col('Security Score:', 'BOLD')}")
    print(f"    [{bar}]")
    print(f"    {col(f'{score}/100', sc)}  Grade: {col(letter, sc)}  — {col(label, sc)}")

    if findings:
        crits = [f for f in findings if f["severity"] == "CRITICAL"]
        mods  = [f for f in findings if f["severity"] == "MODERATE"]
        print(f"\n  {col('Penalty Breakdown:', 'BOLD')}")
        if crits:
            print(f"    Critical : {len(crits)} × -{PENALTY['CRITICAL']} pts = -{len(crits)*PENALTY['CRITICAL']} pts")
        if mods:
            print(f"    Moderate : {len(mods)} × -{PENALTY['MODERATE']} pts = -{len(mods)*PENALTY['MODERATE']} pts")
        print(f"    Base 100  →  Final Score: {col(str(score), sc)}")

    print(f"\n{col(SEP, 'INFO')}\n")

def print_table(results: List[Tuple]):
    if len(results) < 2:
        return
    results = sorted(results, key=lambda x: x[1], reverse=True)
    print(col(f"\n{'═'*66}", "INFO"))
    print(col("  COMPARISON TABLE  (sorted best → worst)", "BOLD"))
    print(col(f"{'═'*66}", "INFO"))
    print(f"  {'File':<26} {'Score':>6}  {'Grade':<7} Status")
    print(col(f"  {'─'*60}", "DIM"))
    for fname, score, letter, label in results:
        sc = score_color(score)
        print(f"  {col(fname[:25],'BOLD'):<36} {col(f'{score}/100', sc):<18} "
              f"{col(letter, sc):<17} {col(label, sc)}")
    print(col(f"{'═'*66}\n", "INFO"))

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def resolve_pcaps(targets: List[str]) -> List[str]:
    paths = []
    for t in targets:
        p = Path(t)
        if p.is_dir():
            paths += sorted(p.glob("*.pcap")) + sorted(p.glob("*.pcapng"))
        elif p.is_file() and p.suffix in (".pcap", ".pcapng"):
            paths.append(p)
        else:
            print(col(f"[WARN] '{t}' is not a pcap file or directory — skipped", "MODERATE"))
    return [str(p) for p in paths]

def main():
    parser = argparse.ArgumentParser(
        description="IPsec/IKEv2 PCAP Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 analyzer.py captures/weak.pcap
  python3 analyzer.py captures/
  python3 analyzer.py strong.pcap medium.pcap weak.pcap
        """
    )
    parser.add_argument("targets", nargs="+",
                        help=".pcap file(s) or directory containing pcaps")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors")
    args = parser.parse_args()

    if args.no_color:
        for k in C: C[k] = ""

    pcaps = resolve_pcaps(args.targets)
    if not pcaps:
        print(col("[ERROR] No valid .pcap files found.", "CRITICAL"))
        sys.exit(1)

    print(col(f"\n{'═'*66}", "INFO"))
    print(col("  IPsec / IKEv2 Security Analyzer", "BOLD"))
    print(col(f"  Analyzing {len(pcaps)} file(s) ...", "DIM"))
    print(col(f"{'═'*66}", "INFO"))

    comparison = []
    for pcap in pcaps:
        if not os.path.isfile(pcap):
            print(col(f"[ERROR] File not found: {pcap}", "CRITICAL"))
            continue

        raw = extract_isakmp_text(pcap)
        if not raw.strip():
            print(col(f"\n[WARN] No IKE/ISAKMP traffic in {pcap} — skipping\n", "MODERATE"))
            continue

        findings = detect_algorithms(raw)
        score    = compute_score(findings)
        letter, label = grade(score)

        print_report(pcap, findings,
                     detect_ike_version(raw),
                     detect_auth_mode(raw),
                     packet_summary(raw),
                     score)
        comparison.append((os.path.basename(pcap), score, letter, label))

    if len(comparison) > 1:
        print_table(comparison)

if __name__ == "__main__":
    main()
