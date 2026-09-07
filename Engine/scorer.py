#!/usr/bin/env python3
"""
engine/scorer.py
================
NIST SP 800-77 Rev.1 compliant IKEv2 security scorer.

Takes ike_parser JSON (dict or file path), applies rule-based deductions,
returns score 0-100 with structured findings list.

No hardcoded demo values — all decisions derived from parsed packet data.
"""

import json, sys, argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Scoring constants — all penalties derived from NIST SP 800-77 Rev.1
# ─────────────────────────────────────────────────────────────────────────────

BASE_SCORE = 100

# Each rule tuple: (rule_id, severity, penalty, title, detail_template, citation, remediation)
# detail_template uses .format(**ctx) where ctx comes from parsed data

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "INFO": 4}

GRADE_MAP = [
    (90, "A", "STRONG"),
    (75, "B", "ACCEPTABLE"),
    (55, "C", "WEAK"),
    (35, "D", "VULNERABLE"),
    (0,  "F", "CRITICAL RISK"),
]


def _grade(score: int) -> Tuple[str, str]:
    for threshold, letter, label in GRADE_MAP:
        if score >= threshold:
            return letter, label
    return "F", "CRITICAL RISK"


# ─────────────────────────────────────────────────────────────────────────────
# Individual rule checkers
# Return list of finding dicts (empty = no issue found)
# ─────────────────────────────────────────────────────────────────────────────

def _finding(rule_id: str, severity: str, penalty: int,
             title: str, detail: str, citation: str,
             remediation: str, pqc_risk: bool = False) -> Dict:
    return {
        "rule_id":     rule_id,
        "severity":    severity,
        "penalty":     penalty,
        "title":       title,
        "detail":      detail,
        "citation":    citation,
        "remediation": remediation,
        "pqc_risk":    pqc_risk,
    }


def check_encryption(p: Dict) -> List[Dict]:
    findings = []
    encr = p.get("ike_sa", {}).get("encryption", {})
    name = encr.get("name", "UNKNOWN")
    bits = encr.get("key_bits")
    aead = encr.get("aead", False)

    # Rule E1 — Broken / obsolete ciphers
    if "3DES" in name or name == "DES":
        findings.append(_finding(
            rule_id    = "E1_BROKEN_CIPHER",
            severity   = "CRITICAL",
            penalty    = 40,
            title      = f"Broken cipher in use: {name}",
            detail     = (
                f"{name} has an effective key strength of {bits} bits. "
                "SWEET32 attack (CVE-2016-2183) exploits birthday-bound collisions after "
                "~2^32 blocks (~785 GB of data under one key). "
                "NIST SP 800-77 Rev.1 §3.1 forbids any cipher other than AES for IKEv2."
            ),
            citation   = "NIST SP 800-77 Rev.1 §3.1; CVE-2016-2183",
            remediation= "Replace with AES-256-GCM: set esp_proposals = aes256gcm16-modp3072",
        ))

    elif name == "NULL":
        findings.append(_finding(
            rule_id    = "E1_NULL_CIPHER",
            severity   = "CRITICAL",
            penalty    = 60,
            title      = "NULL encryption — no confidentiality",
            detail     = (
                "ESP payload transmitted entirely in plaintext. "
                "Any passive observer on the network path has full visibility into data. "
                "NIST SP 800-77 Rev.1 §3.1 mandates AES for all IKEv2 ESP deployments."
            ),
            citation   = "NIST SP 800-77 Rev.1 §3.1",
            remediation= "Use AES-256-GCM (aes256gcm16) for ESP.",
        ))

    elif "AES" in name:
        # Rule E2 — Key length below 256 bits
        if bits is not None and bits < 256:
            findings.append(_finding(
                rule_id    = "E2_WEAK_KEY_LENGTH",
                severity   = "MODERATE",
                penalty    = 15,
                title      = f"Sub-optimal AES key length: {bits}-bit",
                detail     = (
                    f"AES-{bits} provides {bits}-bit symmetric security. "
                    "NIST SP 800-77 Rev.1 Table 1 recommends 256-bit keys for "
                    "long-term confidentiality (classified at SECRET/TOP SECRET level) "
                    "and to maintain adequate margin against algorithmic advances."
                ),
                citation   = "NIST SP 800-77 Rev.1 §3.1 Table 1",
                remediation= "Upgrade to AES-256. In strongSwan: aes256 (CBC) or aes256gcm16 (GCM).",
            ))

        # Rule E3 — CBC mode (no AEAD)
        if not aead:
            findings.append(_finding(
                rule_id    = "E3_NON_AEAD_MODE",
                severity   = "LOW",
                penalty    = 10,
                title      = f"{name} — Non-AEAD mode (integrity separated)",
                detail     = (
                    "CBC mode requires an independent HMAC for integrity. "
                    "Padding oracle attacks (e.g. POODLE-variant) are possible against "
                    "misconfigured CBC implementations. NIST SP 800-77 Rev.1 §3.1 "
                    "recommends AEAD ciphers (GCM) that provide combined auth+encryption."
                ),
                citation   = "NIST SP 800-77 Rev.1 §3.1; RFC 8221 §3",
                remediation= "Switch to AES-GCM: aes256gcm16 in strongSwan esp_proposals.",
            ))

    return findings


def check_integrity(p: Dict) -> List[Dict]:
    findings = []
    integ = p.get("ike_sa", {}).get("integrity", "")

    # Rule I1 — MD5-based integrity
    if "MD5" in integ:
        findings.append(_finding(
            rule_id    = "I1_BROKEN_HASH_MD5",
            severity   = "CRITICAL",
            penalty    = 30,
            title      = f"Cryptographically broken integrity: {integ}",
            detail     = (
                "MD5 is fully broken for cryptographic use (Wang et al., 2004). "
                "Practical collision attacks require <2^24 operations. "
                "NIST SP 800-77 Rev.1 §3.1 explicitly prohibits HMAC-MD5 for IKEv2. "
                "An attacker may forge authentication tags, enabling man-in-the-middle."
            ),
            citation   = "NIST SP 800-77 Rev.1 §3.1; RFC 6151",
            remediation= "Use HMAC-SHA-384 (auth=sha384) or AES-GCM (eliminates separate HMAC).",
        ))

    # Rule I2 — SHA-1-based integrity
    elif "SHA1" in integ or "SHA-1" in integ:
        findings.append(_finding(
            rule_id    = "I2_DEPRECATED_HASH_SHA1",
            severity   = "MODERATE",
            penalty    = 15,
            title      = f"Deprecated integrity algorithm: {integ}",
            detail     = (
                "SHA-1 is deprecated by NIST since 2011 (FIPS 180-4). "
                "The SHAttered attack (2017) demonstrated a practical SHA-1 collision "
                "at ~2^63 operations. NIST SP 800-77 Rev.1 §3.1 recommends SHA-256 minimum; "
                "SHA-384 for higher security classifications."
            ),
            citation   = "NIST SP 800-77 Rev.1 §3.1; NIST SP 800-131A Rev.2",
            remediation= "Replace with HMAC-SHA2-384 (auth=sha384 in strongSwan).",
        ))

    return findings


def check_dh_group(p: Dict) -> List[Dict]:
    findings = []
    dh = p.get("ike_sa", {}).get("dh_group")

    if dh is None:
        findings.append(_finding(
            rule_id    = "D0_DH_NOT_DETECTED",
            severity   = "INFO",
            penalty    = 0,
            title      = "DH group not detected in capture",
            detail     = "No Key Exchange transform found in IKE_SA_INIT proposal. Cannot assess DH strength.",
            citation   = "NIST SP 800-77 Rev.1 §3.4",
            remediation= "Ensure capture contains IKE_SA_INIT frames.",
        ))
        return findings

    name    = dh.get("name", "Unknown")
    bits    = dh.get("modp_bits", 0)
    nist_ok = dh.get("nist_min_ok", False)
    gid     = dh.get("group_id", 0)

    # Rule D1 — DH group below NIST minimum (Group 14 / MODP-2048)
    if not nist_ok or bits < 2048:
        findings.append(_finding(
            rule_id    = "D1_DH_BELOW_NIST_MIN",
            severity   = "HIGH",
            penalty    = 25,
            title      = f"DH group below NIST minimum: {name} ({bits}-bit)",
            detail     = (
                f"NIST SP 800-77 Rev.1 §3.4 requires a minimum of MODP-2048 (DH Group 14) "
                f"or ECP-256. {name} ({bits}-bit) is below this threshold. "
                "The Logjam attack (2015, CVE-2015-4000) demonstrated that MODP-1024 "
                "can be broken by nation-state actors via precomputation. "
                "Sessions using this group may already be decryptable by well-resourced adversaries."
            ),
            citation   = "NIST SP 800-77 Rev.1 §3.4; CVE-2015-4000 (Logjam)",
            remediation= "Use DH Group 15 (MODP-3072) or higher: modp3072 in strongSwan proposals.",
            pqc_risk   = True,
        ))

    # Rule D2 — MODP-based DH (not quantum-safe) — Harvest-Now-Decrypt-Later
    # All MODP groups are vulnerable to Shor's algorithm on a CQ; flag always
    if gid <= 21:  # All current IANA groups are classical; no PQC groups deployed in IKEv2 yet
        sev = "HIGH" if bits >= 2048 else "CRITICAL"
        pen = 0 if bits >= 3072 else 5   # extra penalty for <3072 classical
        findings.append(_finding(
            rule_id    = "D2_HARVEST_NOW_DECRYPT_LATER",
            severity   = "HIGH",
            penalty    = pen,
            title      = f"Harvest-Now-Decrypt-Later risk: {name} is not quantum-resistant",
            detail     = (
                f"{name} (DH Group {gid}) relies on the classical Diffie-Hellman discrete-log "
                "problem, which is broken in polynomial time by Shor's algorithm on a "
                "Cryptographically Relevant Quantum Computer (CRQC). "
                "Adversaries performing 'harvest-now, decrypt-later' attacks can store "
                "encrypted sessions captured today and decrypt them when a CRQC becomes available. "
                "NIST SP 800-77 Rev.1 Appendix C recommends migration to quantum-resistant "
                "key exchange (CRYSTALS-Kyber / ML-KEM, per NIST FIPS 203 draft)."
            ),
            citation   = "NIST SP 800-77 Rev.1 App. C; NIST IR 8309; FIPS 203 (draft)",
            remediation= (
                "Long-term: migrate to IKEv2 + ML-KEM (RFC draft-ietf-ipsecme-ikev2-mlkem). "
                "Near-term: ensure DH ≥ MODP-3072 to raise CRQC attack cost."
            ),
            pqc_risk   = True,
        ))

    return findings


def check_pfs(p: Dict) -> List[Dict]:
    findings = []
    pfs = p.get("pfs", {})
    detected = pfs.get("detected")       # True / False / None
    note     = pfs.get("note", "")

    if detected is False:
        findings.append(_finding(
            rule_id    = "P1_PFS_ABSENT",
            severity   = "HIGH",
            penalty    = 15,
            title      = "Perfect Forward Secrecy (PFS) disabled",
            detail     = (
                "PFS ensures each ESP child SA uses an independent DH key exchange, "
                "so compromise of the long-term IKE key does not expose past session traffic. "
                "NIST SP 800-77 Rev.1 §3.3 strongly recommends PFS for all ESP child SAs. "
                "Without PFS, a single key compromise retrospectively decrypts all recorded traffic."
            ),
            citation   = "NIST SP 800-77 Rev.1 §3.3",
            remediation= (
                "Enable PFS by including a DH group in esp_proposals. "
                "Example: esp_proposals = aes256gcm16-modp3072"
            ),
        ))
    elif detected is None:
        # Not observable — informational only, no penalty
        findings.append(_finding(
            rule_id    = "P0_PFS_UNOBSERVABLE",
            severity   = "INFO",
            penalty    = 0,
            title      = "PFS state not observable in this capture",
            detail     = (
                "PFS for ESP child SAs is negotiated inside encrypted IKE_AUTH payloads "
                "(RFC 7296 §2.14) and confirmed via CREATE_CHILD_SA KE payload. "
                "Neither was visible in this capture. " + note
            ),
            citation   = "NIST SP 800-77 Rev.1 §3.3; RFC 7296 §2.14",
            remediation= (
                "To verify PFS: capture a tunnel rekey event (CREATE_CHILD_SA). "
                "In strongSwan, ensure esp_proposals includes a DH group (e.g. modp3072)."
            ),
        ))
    # detected is True → no finding (good)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Main scorer
# ─────────────────────────────────────────────────────────────────────────────

RULE_CHECKERS = [check_encryption, check_integrity, check_dh_group, check_pfs]


def score(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute security score from ike_parser output dict.
    Returns score dict with findings list, grade, PQC risk flag.
    """
    if "error" in parsed:
        return {"error": parsed["error"], "score": 0, "grade": "F", "findings": []}

    all_findings: List[Dict] = []
    for checker in RULE_CHECKERS:
        all_findings.extend(checker(parsed))

    # Sort: CRITICAL → HIGH → MODERATE → LOW → INFO
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    # Only penalise non-INFO findings
    total_penalty = sum(f["penalty"] for f in all_findings)
    final_score   = max(0, BASE_SCORE - total_penalty)
    letter, label = _grade(final_score)
    pqc_risk      = any(f.get("pqc_risk") for f in all_findings)

    return {
        "file":          parsed.get("file", ""),
        "score":         final_score,
        "grade":         letter,
        "grade_label":   label,
        "total_penalty": total_penalty,
        "pqc_risk":      pqc_risk,
        "ike_summary": {
            "encryption":  parsed.get("ike_sa", {}).get("encryption", {}),
            "integrity":   parsed.get("ike_sa", {}).get("integrity", ""),
            "prf":         parsed.get("ike_sa", {}).get("prf", ""),
            "dh_group":    parsed.get("ike_sa", {}).get("dh_group"),
            "mode":        parsed.get("mode", "tunnel"),
        },
        "findings": all_findings,
    }


def score_pcap(pcap_path: str) -> Dict[str, Any]:
    """Convenience: parse a pcap file then score it."""
    import importlib.util, sys
    from pathlib import Path

    parser_path = Path(__file__).parent / "ike_parser.py"
    spec = importlib.util.spec_from_file_location("ike_parser", parser_path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    parsed = mod.parse_pcap(pcap_path)
    return score(parsed)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="IKEv2 security scorer — NIST SP 800-77 Rev.1 compliant"
    )
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--pcap",  help="Score directly from a .pcap file")
    grp.add_argument("--json",  help="Score from ike_parser JSON file (or '-' for stdin)")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print output")
    args = ap.parse_args()

    if args.pcap:
        result = score_pcap(args.pcap)
    else:
        if args.json == "-":
            parsed = json.load(sys.stdin)
        else:
            with open(args.json) as f:
                parsed = json.load(f)
        result = score(parsed)

    print(json.dumps(result, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
