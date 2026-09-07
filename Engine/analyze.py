#!/usr/bin/env python3
import os, sys, json, argparse, importlib.util
from pathlib import Path

# ── terminal colors ──────────────────────────────────────────────────────────
R  = "\033[91m"; Y  = "\033[93m"; G  = "\033[92m"
C  = "\033[96m"; B  = "\033[1m";  D  = "\033[2m";  E  = "\033[0m"

def col(text, code): return f"{code}{text}{E}"
def bar(score):
    f = score // 2
    clr = G if score >= 75 else Y if score >= 50 else R
    return col("█" * f, clr) + col("░" * (50 - f), D)

SEV_COL = {"CRITICAL": R, "HIGH": R, "MODERATE": Y, "LOW": Y, "INFO": D}

# ── module loader ─────────────────────────────────────────────────────────────
def _load(name):
    p = Path(__file__).parent / "engine" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, p)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

# ── output helpers ────────────────────────────────────────────────────────────
W = 68

def rule(ch="─"): print(col(ch * W, C))
def dbl(ch="═"): print(col(ch * W, C))
def hdr(text):
    dbl()
    print(col(f"  {text}", B))
    dbl()

def section(text): print(f"\n  {col(text, B)}")

def ike_table(ike_sa):
    encr = ike_sa["encryption"]
    dh   = ike_sa.get("dh_group") or {}
    rows = [
        ("Encryption",  f"{encr['name']}  ({encr.get('key_bits') or '—'} bit)"
                        + ("  [AEAD]" if encr.get("aead") else "")),
        ("Integrity",   ike_sa.get("integrity", "—")),
        ("PRF",         ike_sa.get("prf", "—")),
        ("DH Group",    f"{dh.get('name','—')}  ({dh.get('modp_bits','—')} bit)"
                        if dh else "—"),
        ("Mode",        ike_sa.get("mode", "tunnel")),
    ]
    for k, v in rows:
        print(f"    {col(k+':',''):<22}{v}")

def findings_block(findings):
    relevant = [f for f in findings if f["severity"] != "INFO"]
    if not relevant:
        print(f"    {col('No actionable findings.', G)}")
        return
    for f in relevant:
        c = SEV_COL.get(f["severity"], "")
        sev   = col(f"[{f['severity']:<8}]", c)
        title = col(f["title"], c)
        print(f"\n    {sev} {title}")
        # wrap detail at 62 chars
        words, line = f["detail"].split(), "             "
        for w in words:
            if len(line) + len(w) > 72:
                print(f"    {col(line.rstrip(), D)}")
                line = "             " + w + " "
            else:
                line += w + " "
        if line.strip():
            print(f"    {col(line.rstrip(), D)}")
        print(f"    {col('  Ref: ' + f['citation'], D)}")
        print(f"    {col('  Fix: ' + f['remediation'], G)}")

def score_block(score, grade, label, pqc):
    clr = G if score >= 75 else Y if score >= 50 else R
    print(f"\n  {col('Score:', B)}")
    print(f"    [{bar(score)}]")
    print(f"    {col(f'{score}/100', clr)}  Grade {col(grade, clr)}  —  {col(label, clr)}")
    if pqc:
        print(f"\n    {col('⚠  Harvest-Now-Decrypt-Later risk flagged', Y)}")
        print(col("      All classical DH (MODP/ECP) is vulnerable to Shor's algorithm", D))
        print(col("      on a future CRQC. Data captured today may be decrypted later.", D))

def changes_block(changes):
    for field, note in changes:
        print(f"    {col(field+':', B):<28}{note}")

def compare_table(results):
    dbl()
    print(col("  COMPARISON", B))
    dbl()
    print(f"  {'File':<26} {'Score':>6}  {'Grade':<6} Status")
    print(col("  " + "─" * 60, D))
    for name, score, grade, label, pqc in sorted(results, key=lambda x: -x[1]):
        clr = G if score >= 75 else Y if score >= 50 else R
        pqc_flag = col("  ⚠ PQC", Y) if pqc else ""
        print(f"  {col(name[:25], B):<36} {col(str(score).rjust(3), clr)}/100  "
              f"{col(grade, clr):<17} {col(label, clr)}{pqc_flag}")
    dbl()

# ── per-file pipeline ─────────────────────────────────────────────────────────
def run_file(pcap_path, parser_mod, scorer_mod, rem_mod, save_dir=None, no_save=False):
    fname = Path(pcap_path).name

    rule()
    print(col(f"  {fname}", B))
    rule()

    parsed = parser_mod.parse_pcap(str(pcap_path))
    if "error" in parsed:
        print(col(f"  [ERROR] {parsed['error']}", R))
        return None

    scored   = scorer_mod.score(parsed)
    remedied = rem_mod.remediate(scored)

    section("Negotiated IKE SA  (from IKE_SA_INIT — cleartext)")
    ike_table(parsed["ike_sa"])

    note = parsed.get("esp_sa", {}).get("note", "")
    if note:
        print(f"\n    {col('ESP SA:', B)} {col('IKE_AUTH encrypted — inner payloads not visible (RFC 7296 §2.14)', D)}")

    pfs = parsed.get("pfs", {})
    print(f"    {col('PFS:', B):<22}{col(pfs.get('note', '—'), D)}")

    section("Findings")
    findings_block(scored["findings"])

    score_block(scored["score"], scored["grade"], scored["grade_label"], scored["pqc_risk"])

    if remedied["changes"]:
        section("Remediation  (swanctl.conf)")
        changes_block(remedied["changes"])

        save_path = None
        if save_dir:
            save_path = Path(save_dir) / f"{Path(fname).stem}_remediated.conf"
        elif not no_save:
            ans = input(f"\n  Save remediated config? [y/N] ").strip().lower()
            if ans == "y":
                default = Path(pcap_path).parent / f"{Path(fname).stem}_remediated.conf"
                raw = input(f"  Path [{default}]: ").strip()
                save_path = Path(raw) if raw else default

        if save_path:
            save_path.write_text(remedied["swanctl_conf"])
            print(f"\n  {col('Saved →', G)} {save_path}")
    else:
        section("Remediation")
        print(f"    {col('No configuration changes required.', G)}")

    print()
    return (fname, scored["score"], scored["grade"], scored["grade_label"], scored["pqc_risk"])

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="IPsec / IKEv2 PCAP security analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  examples:\n"
               "    python3 analyze.py\n"
               "    python3 analyze.py --folder captures/\n"
               "    python3 analyze.py --folder captures/ --save-configs"
    )
    ap.add_argument("--folder",       help="Folder containing .pcap files")
    ap.add_argument("--save-configs", action="store_true",
                    help="Auto-save remediated configs alongside each pcap")
    ap.add_argument("--no-save", action="store_true",
                    help="Skip save prompt, just display results")
    args = ap.parse_args()

    hdr("IPsec / IKEv2 Security Analyzer")

    folder = args.folder
    if not folder:
        folder = input(col("  Enter path to pcap folder: ", C)).strip()
    folder = Path(folder).expanduser().resolve()

    if not folder.is_dir():
        print(col(f"[ERROR] Not a directory: {folder}", R))
        sys.exit(1)

    pcaps = sorted(folder.glob("*.pcap")) + sorted(folder.glob("*.pcapng"))
    if not pcaps:
        print(col(f"  No .pcap files found in {folder}", Y))
        sys.exit(1)

    print(col(f"\n  Found {len(pcaps)} capture(s) in {folder}\n", D))

    try:
        parser_mod = _load("ike_parser")
        scorer_mod = _load("scorer")
        rem_mod    = _load("remediate")
    except Exception as e:
        print(col(f"[ERROR] Could not load engine modules: {e}", R))
        sys.exit(1)

    save_dir = str(folder) if args.save_configs else None
    results  = []

    for p in pcaps:
        r = run_file(p, parser_mod, scorer_mod, rem_mod, save_dir=save_dir,
                     no_save=args.no_save)
        if r:
            results.append(r)

    if len(results) > 1:
        print()
        compare_table(results)

if __name__ == "__main__":
    main()
