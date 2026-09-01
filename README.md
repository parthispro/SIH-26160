# SIH-26160
This is our repository for showcasing our project for SIH 2026 , Problem Statement number - 26160 AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

**Smart India Hackathon 2026 — Problem Statement SIH26160**
**Organization:** National Technical Research Organisation (NTRO)
**Category:** Software | **Theme:** Blockchain & Cybersecurity

---

## 1. Problem Statement

IPsec is widely used to secure enterprise, government, and cloud network traffic, but its actual security depends entirely on *how* it's configured — the chosen cipher suite, key exchange method, and whether Perfect Forward Secrecy (PFS) is enabled. Misconfigured or outdated IPsec deployments (weak ciphers, deprecated hash algorithms, small Diffie-Hellman groups) look identical to secure ones from the outside — the tunnel "works" either way — but are silently vulnerable.

Today, verifying an IPsec deployment's real security posture requires a human expert manually inspecting raw packet captures in tools like Wireshark. This project automates that inspection.

## 2. What This Project Does

Given a `.pcap` network capture containing an IPsec tunnel's handshake, this tool:

1. **Parses** the cleartext IKE (Internet Key Exchange) negotiation packets to extract the negotiated encryption algorithm, Diffie-Hellman group, and whether PFS was used.
2. **Scores** the configuration against known security guidelines (NIST SP 800-77 Rev.1), producing a 0–100 risk score with specific findings.
3. **Flags** classical (non-quantum-resistant) DH groups as a "Harvest-Now-Decrypt-Later" (HNDL) risk — traffic encrypted today with weak key exchange could be recorded now and decrypted later once quantum computers mature.
4. **Generates** a corrected `ipsec.conf` snippet using secure parameter choices, so a misconfiguration can be fixed immediately.
5. Presents all of this through a simple interactive dashboard.

**Important framing:** the vast majority of this tool is deterministic rule-based logic (packet field extraction + a security checklist), not machine learning. The only genuinely AI/ML component (a classifier that infers traffic type — e.g., video vs. web browsing — from encrypted ESP packet size/timing patterns, without ever decrypting anything) was **descoped for the hackathon submission** due to time constraints and is documented below as future work. We were explicit about this distinction with judges: rules process the cleartext IKE handshake; only a stretch-goal ML model would touch encrypted traffic metadata.

## 3. Why This Matters

- IPsec misconfigurations (weak ciphers, deprecated hashes, small DH groups, disabled PFS) are common and invisible without expert manual review.
- Existing protocol analysis tools (Wireshark, tcpdump) provide raw visibility but require expert interpretation — there's no automated, actionable "is this secure?" answer.
- Post-quantum readiness is an emerging requirement for government/defense infrastructure; this tool provides an early, cheap way to flag deployments still using classical (non-PQC) key exchange.

## 4. Architecture

\`\`\`
                [ Captured .pcap file ]
                          |
                          v
          +-------------------------------+
          |   IKE Negotiation Parser       |
          |   (reads cleartext IKE_SA_INIT |
          |    / IKE_AUTH payloads)        |
          |   Extracts: cipher, DH group,  |
          |   PFS status, tunnel mode      |
          +-------------------------------+
                          |
                          v
          +-------------------------------+
          |   Rule-Based Scoring Engine    |
          |   - NIST SP 800-77 Rev.1       |
          |     compliance checks          |
          |   - Deducts points per finding |
          |   - Flags HNDL / PQC risk      |
          +-------------------------------+
                          |
                          v
          +-------------------------------+
          |   Remediation Generator        |
          |   Produces a corrected         |
          |   ipsec.conf snippet           |
          +-------------------------------+
                          |
                          v
          +-------------------------------+
          |   Dashboard (Streamlit)        |
          |   - Score + findings table     |
          |   - PQC risk flag              |
          |   - Downloadable fixed config  |
          +-------------------------------+
\`\`\`

## 5. Tech Stack

| Component | Tool |
|---|---|
| Test environment | Docker containers running strongSwan (simulating two IPsec endpoints) |
| Packet capture | `tcpdump` |
| Packet parsing | `pyshark` / `scapy` |
| Scoring logic | Python (rule-based, no ML) |
| Dashboard | Streamlit |
| Report export | `fpdf2` |
| OS | Kali Linux (disk install) |

## 6. Reproducing the Test Environment

The project simulates two IPsec endpoints ("office-a" and "office-b") using Docker containers instead of physical machines, since standing up real cross-network IPsec tunnels for testing is unnecessary overhead — the protocol behavior is identical.

### 6.1 Prerequisites

\`\`\`bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y strongswan strongswan-pki tcpdump tshark python3 python3-pip python3-venv git curl ca-certificates

# Docker
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER && newgrp docker
\`\`\`

> **Known issue:** on some live-boot/overlay-filesystem Linux setups, Docker's default `overlay2` storage driver fails to start containers (`failed to mount ... fstype: overlay ... err: invalid argument`) because you can't stack overlayfs on overlayfs. Fix by forcing the `vfs` storage driver:
> \`\`\`bash
> sudo mkdir -p /etc/docker
> echo '{ "storage-driver": "vfs" }' | sudo tee /etc/docker/daemon.json
> sudo systemctl restart docker
> \`\`\`
> This does not occur on a normal disk-based Linux install.

### 6.2 Python environment

\`\`\`bash
mkdir -p ~/sih26160/{engine,captures,configs,dashboard}
cd ~/sih26160
python3 -m venv venv && source venv/bin/activate
pip install scapy pyshark pandas scikit-learn streamlit fpdf2 numpy
\`\`\`

### 6.3 Build the two-container testbed

\`\`\`bash
docker network create --subnet=172.28.0.0/16 ipsec-net

docker run -dit --name office-a --network ipsec-net --ip 172.28.0.10 \\
  --cap-add=NET_ADMIN --cap-add=NET_RAW --privileged debian:bookworm bash
docker run -dit --name office-b --network ipsec-net --ip 172.28.0.20 \\
  --cap-add=NET_ADMIN --cap-add=NET_RAW --privileged debian:bookworm bash

docker exec office-a bash -c "apt update && apt install -y strongswan strongswan-swanctl iproute2 iputils-ping tcpdump"
docker exec office-b bash -c "apt update && apt install -y strongswan strongswan-swanctl iproute2 iputils-ping tcpdump"
\`\`\`

### 6.4 Configure and capture each security profile

Three profiles are used to demonstrate the analyzer distinguishing strong vs. weak configurations:

| Profile | Cipher | DH Group | PFS |
|---|---|---|---|
| **Strong** | AES-256-GCM | Group 19+ (ECC, MODP 3072) | Enabled |
| **Medium** | AES-128-CBC / SHA-1 | MODP 2048 (Group 14) | Enabled |
| **Weak** | AES-128-CBC / SHA-1 | MODP 1024 (Group 2) | Disabled |

Example `swanctl.conf` (Strong profile, `office-a` side — mirror IPs for `office-b`):

\`\`\`
connections {
   office-tunnel {
      local_addrs  = 172.28.0.10
      remote_addrs = 172.28.0.20
      local { auth = psk }
      remote { auth = psk }
      children {
         office-child {
            local_ts  = 172.28.0.10/32
            remote_ts = 172.28.0.20/32
            mode = tunnel
            esp_proposals = aes256gcm16-modp3072
         }
      }
      version = 2
      proposals = aes256-sha384-modp3072
   }
}
secrets {
   ike-1 {
      id-1 = 172.28.0.10
      id-2 = 172.28.0.20
      secret = "TestPSK123!"
   }
}
\`\`\`

Load and capture — **critically, start the packet capture BEFORE initiating the tunnel**, not after:

\`\`\`bash
docker exec office-a bash -c "ipsec start && sleep 2 && swanctl --load-all"
docker exec office-b bash -c "ipsec start && sleep 2 && swanctl --load-all"

docker exec office-a rm -f /tmp/strong.pcap
docker exec office-a bash -c "tcpdump -i any -w /tmp/strong.pcap host 172.28.0.20 -c 13" & sleep 1
docker exec office-a swanctl --initiate --child office-child
docker exec office-a ping -c 3 172.28.0.20
wait

docker cp office-a:/tmp/strong.pcap ~/sih26160/captures/strong.pcap
\`\`\`

Repeat with the Medium and Weak `swanctl.conf` variants (terminate the existing tunnel first with `swanctl --terminate --ike office-tunnel`, overwrite the config, reload, then repeat the capture-before-initiate sequence) to produce `medium.pcap` and `weak.pcap`.

> **Lesson learned (see §8):** capturing traffic *after* a tunnel is already established only captures ESP (encrypted) and ICMP traffic — the IKE negotiation itself, which is where the cipher/DH group/PFS information actually lives in cleartext, happens seconds earlier and will be missed entirely. Always start the capture first, then bring the tunnel up.

## 7. Running the Analyzer

\`\`\`bash
source venv/bin/activate
streamlit run dashboard/app.py
\`\`\`

Upload any of the three sample pcaps (or a real IPsec capture) to see the extracted configuration, security score, findings, PQC risk flag, and a downloadable hardened `ipsec.conf`.

## 8. Design Decisions & Lessons Learned

This section is kept intentionally honest, since it reflects real engineering judgment calls made under time pressure — useful both for future contributors and for transparency with evaluators.

- **No fabricated results, ever.** Every score, finding, and classification shown by the dashboard is computed live from the uploaded file. No dashboard metric is hardcoded or pre-baked, even for demo purposes.
- **Rules vs. AI, clearly separated.** The IKE parser and scoring engine are deterministic logic, not machine learning, and are described as such. The only place ML would legitimately apply — inferring encrypted traffic type from packet size/timing metadata — was scoped out for time and documented as future work rather than faked with a token 3-sample "trained" classifier.
- **Filename-based inference was identified and rejected.** During development, an early version of the parser (built with AI coding assistance) inferred DH group and PFS status from the pcap's *filename* rather than its actual packet contents, because the initial captures didn't include the IKE negotiation packets. This was caught before submission and fixed by recapturing traffic starting *before* tunnel initiation, so the parser genuinely reads DH group and PFS from the real SA proposal payloads. A parser that depends on filenames would fail (or worse, silently mislead) the moment a judge uploaded a renamed file.
- **Byte-substring matching was avoided for the IKE parser.** An early draft searched for hardcoded byte sequences (e.g., a specific 2-byte pattern to detect AES-128-CBC) directly in raw payload bytes. This is unreliable, since coincidental byte matches in unrelated fields can produce false positives. The parser uses proper structured protocol dissection (`pyshark`) instead.
- **Scope was deliberately cut under time pressure**, in this order of priority: (1) ML traffic classifier — cut entirely; (2) IKEv1 support — out of scope, IKEv2 only; (3) live network capture mode — out of scope, pcap upload only; (4) number of security profiles — capped at 3 (Strong/Medium/Weak) rather than the full matrix of ciphers/modes/traffic types described in the original problem statement.

## 9. Known Limitations / Future Work

- **IKEv2 only** — IKEv1 negotiation is not parsed.
- **Pcap upload only** — no live network interface capture mode yet.
- **Three security profiles** — a production version would need to handle a wider matrix of cipher suites, IKE versions, and NAT-traversal scenarios.
- **ML traffic classifier not implemented** — the ability to infer application traffic type (VoIP, video, web) from encrypted ESP packet metadata alone (packet size distribution, inter-arrival timing) is a natural, well-precedented extension but requires a properly sized labeled dataset that wasn't feasible to collect within the hackathon timeline.
- **NIST citation mapping is manually curated**, not automatically pulled from a live/updatable compliance database.

## 10. Team & Acknowledgments

- Problem Statement: SIH26160, National Technical Research Organisation (NTRO)
- Built for Smart India Hackathon 2026
- Development assisted by Claude (Anthropic) for architecture planning, debugging, and code review, and by an AI coding agent (Antigravity CLI) for implementation of the parsing/scoring engine, under close human supervision to verify all outputs against real captured data.

## 11. DISCLAMER!!!
this is not an final / propper usable model and is not recomended to use on offical / real .pcap files for analysis.
# THIS IS JUST A BASIC PROTOTYPE!!
