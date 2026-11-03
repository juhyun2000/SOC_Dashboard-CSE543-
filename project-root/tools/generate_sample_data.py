"""
Generate a larger SYNTHETIC dataset for the Vulnerability Risk dashboard.

Writes project-root/app/data/assets.csv and findings.csv
(same columns as the hand-made sample from Step 2).

Some problems are planted on purpose so later steps have something to find:
  - 3 assets with no owner
  - 5 assets not scanned in the last 30+ days
  - 4 devices that show up in scans but are not in the asset list
  - 5 tickets marked "Remediated" that the latest scan still sees

Usage:
    python project-root/tools/generate_sample_data.py
    python project-root/tools/generate_sample_data.py --seed 7 --as-of 2026-11-01
"""

import argparse
import os
import random
from datetime import date, timedelta

import pandas as pd

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app", "data")

# (business unit, data classification, services it runs)
# Service names match the log components, so findings can be linked to logs later
UNITS = [
    ("Student Information Systems", "FERPA", ["AuthService", "DBConnector", "WebApp"]),
    ("Campus Health Services", "HIPAA", ["WebApp", "DBConnector", "BackupManager"]),
    ("Parking & Transit Payments", "PCI", ["PaymentService", "PaymentService", "WebApp"]),
    ("Research Computing", "CUI", ["Kernel", "DBConnector", "BackupManager"]),
    ("HR & Payroll", "Internal", ["AuthService", "DBConnector"]),
    ("University Library", "Public", ["WebApp"]),
    ("Enterprise Infrastructure", "Internal", ["Firewall", "Antivirus", "PatchDaemon", "AuthService"]),
    ("Marketing & Web", "Public", ["WebApp"]),
]
OWNERS = ["A. Patel", "M. Garcia", "K. Nguyen", "D. Johnson", "S. Kim", "R. Thompson", "L. Chen", "T. Okafor"]
ENVIRONMENTS = ["prod", "prod", "prod", "stag", "dev"]  # most servers are production
REGULATED = ("FERPA", "HIPAA", "PCI", "CUI")

# (cve, title, cvss, epss, kev, attack_technique, attack_tactic)
CATALOG = [
    # Known exploited (CISA KEV)
    ("CVE-2021-44228", "Apache Log4j RCE (Log4Shell)", 10.0, 0.97, "Yes", "T1190", "TA0001"),
    ("CVE-2021-34527", "Windows Print Spooler RCE (PrintNightmare)", 8.8, 0.94, "Yes", "T1068", "TA0004"),
    ("CVE-2023-4966", "Citrix NetScaler session token leak (Citrix Bleed)", 7.5, 0.96, "Yes", "T1190", "TA0001"),
    ("CVE-2017-0144", "Windows SMBv1 RCE (EternalBlue)", 8.1, 0.96, "Yes", "T1210", "TA0008"),
    ("CVE-2020-1472", "Netlogon elevation of privilege (Zerologon)", 10.0, 0.95, "Yes", "T1068", "TA0004"),
    ("CVE-2023-34362", "MOVEit Transfer SQL injection", 9.8, 0.95, "Yes", "T1190", "TA0001"),
    ("CVE-2023-44487", "HTTP/2 Rapid Reset DoS", 7.5, 0.80, "Yes", "T1499", "TA0040"),
    # Not known to be exploited
    ("CVE-2023-38545", "curl SOCKS5 heap buffer overflow", 9.8, 0.02, "No", "T1203", "TA0002"),
    ("CVE-2022-0778", "OpenSSL infinite loop (DoS)", 7.5, 0.03, "No", "T1499", "TA0040"),
    ("CVE-2023-48795", "SSH Terrapin prefix truncation", 5.9, 0.60, "No", "T1557", "TA0006"),
    ("", "Default administrative credentials", 9.8, 0.0, "No", "T1078.001; T1110", "TA0001; TA0006"),
    ("", "SMB signing not required", 5.3, 0.0, "No", "T1557", "TA0006"),
    ("", "TLS 1.0/1.1 protocol enabled", 6.5, 0.0, "No", "T1557", "TA0006"),
    ("", "SSL certificate expired", 5.3, 0.0, "No", "", ""),
    ("", "Unsupported operating system version", 10.0, 0.0, "No", "", ""),
    ("", "Missing endpoint protection agent", 7.0, 0.0, "No", "", ""),
    ("", "Web server directory listing enabled", 5.3, 0.0, "No", "", ""),
]
STATUSES = ["Open", "In Progress", "Remediated", "Risk Accepted"]
STATUS_WEIGHTS = [55, 25, 12, 8]


def make_assets(as_of):
    """Create 6-8 servers for each business unit."""
    assets = []
    n = 0
    for unit, data_class, services in UNITS:
        for _ in range(random.randint(6, 8)):
            n += 1
            service = random.choice(services)
            env = random.choice(ENVIRONMENTS)

            # Production systems holding regulated data are the most critical
            if env == "prod" and data_class in REGULATED:
                criticality = random.choice(["Critical", "High"])
            elif env == "prod":
                criticality = random.choice(["High", "Medium"])
            else:
                criticality = random.choice(["Medium", "Low"])

            # Only some production web / payment / firewall systems face the internet
            internet = env == "prod" and service in ("WebApp", "PaymentService", "Firewall") and random.random() < 0.7

            assets.append({
                "asset_id": f"AST-{n:03d}",
                "hostname": f"{service.lower()}-{env}-{n:02d}",
                "business_unit": unit,
                "system_owner": random.choice(OWNERS),
                "service": service,
                "criticality": criticality,
                "data_classification": data_class if env != "dev" else "Internal",
                "internet_facing": "Yes" if internet else "No",
                "lifecycle_status": "Active",
                "last_scan_date": (as_of - timedelta(days=random.randint(0, 7))).isoformat(),
            })
    return assets


def plant_asset_problems(assets, as_of):
    """Break a few asset records on purpose."""
    for a in random.sample(assets, 3):          # nobody is responsible for these
        a["system_owner"] = ""
    for a in random.sample(assets, 5):          # forgotten by the scanner
        a["last_scan_date"] = (as_of - timedelta(days=random.randint(40, 120))).isoformat()


def pick_findings(k):
    """Pick k different catalog entries. Known-exploited (KEV) ones are picked less often."""
    weights = [1 if item[4] == "Yes" else 3 for item in CATALOG]
    picked = set()
    while len(picked) < k:
        picked.add(random.choices(range(len(CATALOG)), weights=weights)[0])
    return [CATALOG[i] for i in sorted(picked)]


def make_findings(assets, as_of):
    """Give every scanned host 2-6 findings from the catalog."""
    hosts = [(a["asset_id"], a["hostname"], date.fromisoformat(a["last_scan_date"])) for a in assets]
    # Devices the scanner sees that are NOT in the asset list (no asset_id)
    for name in ["webapp-prod-x17", "rpi-lab-cam-02", "desktop-7hq2k", "nas-backup-old"]:
        hosts.append(("", name, as_of - timedelta(days=1)))

    findings = []
    scan_dates = {}
    for asset_id, hostname, scan_date in hosts:
        scan_dates[hostname] = scan_date
        for cve, title, cvss, epss, kev, tech, tactic in pick_findings(random.randint(2, 6)):
            status = random.choices(STATUSES, weights=STATUS_WEIGHTS)[0]
            # Most findings are recent; some have been open a long time
            age = random.randint(10, 45) if random.random() < 0.7 else random.randint(46, 150)
            first_seen = scan_date - timedelta(days=age)
            # A real fix disappears from later scans, so it was last seen before the latest scan
            last_seen = scan_date - timedelta(days=random.randint(1, age)) if status == "Remediated" else scan_date
            num = len(findings) + 1
            findings.append({
                "finding_id": f"F-{num:04d}",
                "asset_id": asset_id,
                "hostname": hostname,
                "cve": cve,
                "title": title,
                "cvss": cvss,
                "epss": epss,
                "kev": kev,
                "attack_technique": tech,
                "attack_tactic": tactic,
                "first_seen": first_seen.isoformat(),
                "last_seen": last_seen.isoformat(),
                "ticket_id": f"VUL{num:07d}",
                "ticket_status": status,
            })
    return findings, scan_dates


def plant_unverified_fixes(findings, scan_dates):
    """Some tickets were closed, but the latest scan still finds the problem."""
    fixed = [f for f in findings if f["ticket_status"] == "Remediated"]
    for f in random.sample(fixed, min(5, len(fixed))):
        f["last_seen"] = scan_dates[f["hostname"]].isoformat()


def main():
    ap = argparse.ArgumentParser(description="Generate synthetic assets and vulnerability findings")
    ap.add_argument("--seed", type=int, default=543, help="random seed (same seed = same data)")
    ap.add_argument("--as-of", default=date.today().isoformat(), help="date of the latest scan, YYYY-MM-DD")
    args = ap.parse_args()

    random.seed(args.seed)
    as_of = date.fromisoformat(args.as_of)

    assets = make_assets(as_of)
    plant_asset_problems(assets, as_of)
    findings, scan_dates = make_findings(assets, as_of)
    plant_unverified_fixes(findings, scan_dates)

    os.makedirs(DATA_DIR, exist_ok=True)
    pd.DataFrame(assets).to_csv(os.path.join(DATA_DIR, "assets.csv"), index=False)
    pd.DataFrame(findings).to_csv(os.path.join(DATA_DIR, "findings.csv"), index=False)
    print(f"✅ {len(assets)} assets and {len(findings)} findings written to {os.path.normpath(DATA_DIR)}")


if __name__ == "__main__":
    main()
