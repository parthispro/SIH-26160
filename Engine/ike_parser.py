#!/usr/bin/env python3
"""
engine/ike_parser.py
====================
Extract IKEv2 negotiation parameters from a PCAP file.

Data source: tshark packet dissection only — zero filename inference.

IKE_SA_INIT (cleartext): encryption, integrity, PRF, DH group
IKE_AUTH (encrypted):   inner payloads not accessible; noted as opaque
PFS inference:          requires CREATE_CHILD_SA exchange with KE payload
                        or swanctl/ipsec.conf (out of scope for pcap-only mode)

Output: JSON with all fields populated from packet bytes.
"""

import subprocess, re, json, sys, argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── IANA IKEv2 registries ──────────────────────────────────────────────────────
#   (name, effective_bits, is_aead)
ENCR_MAP: Dict[int, Tuple[str, Optional[int], bool]] = {
    3:  ("3DES",        112,  False),
    6:  ("DES",         56,   False),
    11: ("NULL",        0,    False),
    12: ("AES-CBC",     None, False),
    18: ("AES-GCM-8",  None, True),
    19: ("AES-GCM-12", None, True),
    20: ("AES-GCM-16", None, True),
    23: ("ChaCha20-Poly1305", 256, True),
}

INTEG_MAP: Dict[int, str] = {
    0:  "NONE",
    1:  "HMAC-MD5-96",
    2:  "HMAC-SHA1-96",
    5:  "HMAC-SHA1-160",
    12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192",
    14: "HMAC-SHA2-512-256",
}

PRF_MAP: Dict[int, str] = {
    1: "PRF-HMAC-MD5",
    2: "PRF-HMAC-SHA1",
    5: "PRF-HMAC-SHA2-256",
    6: "PRF-HMAC-SHA2-384",
    7: "PRF-HMAC-SHA2-512",
}

#   (name, modp_bits, nist_group_min_ok)
DH_MAP: Dict[int, Tuple[str, int, bool]] = {
    1:  ("MODP-768",   768,   False),
    2:  ("MODP-1024",  1024,  False),
    5:  ("MODP-1536",  1536,  False),
    14: ("MODP-2048",  2048,  True),
    15: ("MODP-3072",  3072,  True),
    16: ("MODP-4096",  4096,  True),
    17: ("MODP-6144",  6144,  True),
    18: ("MODP-8192",  8192,  True),
    19: ("ECP-256",    256,   True),
    20: ("ECP-384",    384,   True),
    21: ("ECP-521",    521,   True),
}

AUTH_MAP: Dict[int, str] = {
    1: "RSA-Signature",
    2: "Pre-Shared-Key",
    3: "DSS-Signature",
    9: "ECDSA-P256",
    10: "ECDSA-P384",
    11: "ECDSA-P521",
    14: "Digital-Signature (RFC 7427)",
}

# Transform type IDs (IKEv2 RFC 7296 §3.3.2)
TF_ENCR  = 1
TF_PRF   = 2
TF_INTEG = 3
TF_DH    = 4
TF_ESN   = 5

# Exchange type IDs
EX_IKE_SA_INIT     = 34
EX_IKE_AUTH        = 35
EX_CREATE_CHILD_SA = 36
EX_INFORMATIONAL   = 37


# ─────────────────────────────────────────────────────────────────────────────
# tshark helpers
# ─────────────────────────────────────────────────────────────────────────────

def _tshark_verbose(pcap: str) -> str:
    r = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "isakmp", "-V"],
        capture_output=True, text=True, timeout=60
    )
    return r.stdout


def _tshark_fields(pcap: str, *fields) -> str:
    """Run tshark in -T fields mode for fast numeric extraction."""
    cmd = ["tshark", "-r", pcap, "-Y", "isakmp", "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return r.stdout


# ─────────────────────────────────────────────────────────────────────────────
# Per-frame verbose parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_transforms(block: str) -> Tuple[List[Dict], List[Dict]]:
    """
    Walk tshark verbose block, return (ike_transforms, esp_transforms).
    Context switches on 'Protocol ID: IKE (1)' vs 'Protocol ID: ESP (3)'.
    """
    ike_tf: List[Dict] = []
    esp_tf: List[Dict] = []
    cur     = ike_tf
    cur_type: Optional[int] = None

    for line in block.splitlines():
        # Protocol context — switch bucket
        pm = re.search(r'Protocol ID:\s+(\w+)\s+\((\d+)\)', line, re.IGNORECASE)
        if pm:
            pid = int(pm.group(2))
            # 1=IKE/IKEv2, 3=ESP, 2=AH
            if pid == 3:
                cur = esp_tf
            elif pid in (1, 50):   # IKEv2=1 per IANA, some versions say 50
                cur = ike_tf
            cur_type = None
            continue

        # Transform type
        tm = re.search(r'Transform Type:\s+.+?\((\w+)\)\s+\((\d+)\)', line)
        if tm:
            cur_type = int(tm.group(2))
            continue

        # Transform ID
        im = re.search(r'Transform ID \(\w+\):\s+.+?\((\d+)\)\s*$', line)
        if im and cur_type is not None:
            cur.append({"type": cur_type, "id": int(im.group(1)), "key_len": None})
            continue

        # Key Exchange Method standalone line (fallback for DH group)
        # e.g. "Key Exchange Method: 3072 bit MODP group (15)"
        ke_m = re.search(r'Key Exchange Method:\s+.+?\((\d+)\)\s*$', line)
        if ke_m and cur_type is None:
            # This is a standalone KE line outside a Transform block — skip
            # (already captured via Transform ID above if transform block present)
            pass

        # Key length attribute (two possible patterns from tshark)
        kl = re.search(r'Key Length:\s+(\d+)', line)
        if kl and cur:
            cur[-1]["key_len"] = int(kl.group(1))

    return ike_tf, esp_tf


def _first(transforms: List[Dict], tf_type: int) -> Optional[Dict]:
    return next((t for t in transforms if t["type"] == tf_type), None)


def _resolve_encr(tf: Optional[Dict]) -> Dict:
    if tf is None:
        return {"name": "UNKNOWN", "key_bits": None, "aead": False}
    name, bits, aead = ENCR_MAP.get(tf["id"], (f"ENCR-id{tf['id']}", None, False))
    if tf.get("key_len"):
        bits = tf["key_len"]
    return {"name": name, "key_bits": bits, "aead": aead}


def _resolve_dh(tf: Optional[Dict]) -> Optional[Dict]:
    if tf is None:
        return None
    name, bits, ok = DH_MAP.get(tf["id"], (f"DH-grp{tf['id']}", 0, False))
    return {
        "name":         name,
        "group_id":     tf["id"],
        "modp_bits":    bits,
        "nist_min_ok":  ok,
    }


# ─────────────────────────────────────────────────────────────────────────────
# PFS detection via CREATE_CHILD_SA
# ─────────────────────────────────────────────────────────────────────────────

def _detect_pfs(raw: str) -> Tuple[Optional[bool], str]:
    """
    PFS = forward secrecy for child (ESP) SAs.
    In IKEv2, PFS is confirmed when CREATE_CHILD_SA carries a KE payload.
    IKE_AUTH child SA proposal is encrypted; CREATE_CHILD_SA is also encrypted
    but the KE payload TYPE in the outer header is visible via 'isakmp.nextpayload'.

    Returns (pfs_detected: bool|None, note: str)
    None means "not determinable from this capture".
    """
    # Check if CREATE_CHILD_SA exchange exists at all
    has_child_rekey = bool(re.search(r'Exchange type:\s+CREATE_CHILD_SA\s+\(36\)', raw))

    if not has_child_rekey:
        return None, (
            "CREATE_CHILD_SA not in capture — PFS state unobservable. "
            "Capture a rekey event or inspect swanctl esp_proposals."
        )

    # In CREATE_CHILD_SA, a KE payload (type 34) in outer next-payload chain
    # signals PFS. tshark shows this even when content is encrypted.
    # We look for KE payload chained inside the Encrypted payload header.
    # Practical proxy: if a Key Exchange payload is listed in CREATE_CHILD_SA frame.
    child_blocks = []
    for block in re.split(r'(?=^Frame \d+:)', raw, flags=re.MULTILINE):
        if re.search(r'Exchange type:\s+CREATE_CHILD_SA', block):
            child_blocks.append(block)

    for block in child_blocks:
        if re.search(r'Payload: Key Exchange', block, re.IGNORECASE):
            return True, "KE payload present in CREATE_CHILD_SA — PFS confirmed."

    return False, "CREATE_CHILD_SA present but no KE payload observed — PFS not in use."


# ─────────────────────────────────────────────────────────────────────────────
# Main parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_pcap(pcap_path: str) -> Dict[str, Any]:
    """
    Parse IKEv2 negotiation from pcap_path.
    Returns structured dict with all parameters sourced from packet bytes.
    """
    path = str(Path(pcap_path).resolve())
    raw  = _tshark_verbose(path)

    if not raw.strip():
        return {
            "error": "No IKE/ISAKMP traffic found in capture",
            "file": path,
            "hint": "Ensure the pcap contains IKEv2 IKE_SA_INIT packets."
        }

    # Split verbose output into per-frame blocks
    frames = [f for f in re.split(r'(?=^Frame \d+:)', raw, flags=re.MULTILINE)
              if f.strip()]

    # Collectors
    ike_sa_init_tf: List[Dict] = []   # IKE SA transforms (from IKE_SA_INIT)
    esp_sa_tf:      List[Dict] = []   # ESP SA transforms (from IKE_AUTH — usually empty, encrypted)
    exchange_types_seen = set()

    for block in frames:
        ex_m = re.search(r'Exchange type:\s+\S+\s+\((\d+)\)', block)
        if not ex_m:
            continue
        ex = int(ex_m.group(1))
        exchange_types_seen.add(ex)

        ike_tf, esp_tf = _parse_transforms(block)

        if ex == EX_IKE_SA_INIT and ike_tf and not ike_sa_init_tf:
            ike_sa_init_tf = ike_tf   # use first IKE_SA_INIT (initiator proposal)

        if ex == EX_IKE_AUTH and esp_tf and not esp_sa_tf:
            esp_sa_tf = esp_tf        # ESP SA in IKE_AUTH (only if not encrypted)

    # Resolve IKE SA fields
    encr_tf   = _first(ike_sa_init_tf, TF_ENCR)
    integ_tf  = _first(ike_sa_init_tf, TF_INTEG)
    prf_tf    = _first(ike_sa_init_tf, TF_PRF)
    dh_tf     = _first(ike_sa_init_tf, TF_DH)

    ike_encr  = _resolve_encr(encr_tf)
    ike_dh    = _resolve_dh(dh_tf)
    ike_integ = INTEG_MAP.get(integ_tf["id"], f"INTEG-id{integ_tf['id']}") if integ_tf else "UNKNOWN"
    ike_prf   = PRF_MAP.get(prf_tf["id"], f"PRF-id{prf_tf['id']}") if prf_tf else "UNKNOWN"

    # ESP SA (visible only if IKE_AUTH inner payloads are decryptable)
    esp_encr_tf  = _first(esp_sa_tf, TF_ENCR)
    esp_integ_tf = _first(esp_sa_tf, TF_INTEG)
    esp_dh_tf    = _first(esp_sa_tf, TF_DH)

    esp_encr  = _resolve_encr(esp_encr_tf)  if esp_encr_tf  else None
    esp_dh    = _resolve_dh(esp_dh_tf)      if esp_dh_tf    else None
    esp_integ = INTEG_MAP.get(esp_integ_tf["id"], f"INTEG-id{esp_integ_tf['id']}") if esp_integ_tf else None

    # PFS detection
    pfs_detected, pfs_note = _detect_pfs(raw)

    # Transport mode
    transport_mode = bool(re.search(r'USE_TRANSPORT_MODE', raw))

    return {
        "file": path,
        "parser_version": "1.0",
        "ike_version": "IKEv2",
        "mode": "transport" if transport_mode else "tunnel",
        "exchanges_observed": sorted(exchange_types_seen),
        "ike_sa": {
            "encryption":  ike_encr,
            "integrity":   ike_integ,
            "prf":         ike_prf,
            "dh_group":    ike_dh,
        },
        "esp_sa": {
            "visible_in_pcap": bool(esp_sa_tf),
            "encryption":  esp_encr,
            "integrity":   esp_integ,
            "dh_group":    esp_dh,
            "note": (
                "IKE_AUTH inner payloads are encrypted per RFC 7296 §2.14. "
                "ESP SA params not directly observable; IKE SA params used for scoring."
                if not esp_sa_tf else "ESP SA params extracted from IKE_AUTH."
            ),
        },
        "pfs": {
            "detected": pfs_detected,
            "note":     pfs_note,
        },
        "auth_method": "Unknown (IKE_AUTH payload encrypted)",
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="IKEv2 PCAP parser — extracts negotiation params to JSON"
    )
    ap.add_argument("pcap", help="Path to .pcap file")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print output")
    args = ap.parse_args()

    result = parse_pcap(args.pcap)
    print(json.dumps(result, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
