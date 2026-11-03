"""
vuln_engine.py: risk-based vulnerability management logic.
No screen code here, only calculations, so each part is easy to test.
"""

import pandas as pd


def load_data(data_dir):
    """Read the asset list and the vulnerability findings."""
    assets = pd.read_csv(f"{data_dir}/assets.csv")
    findings = pd.read_csv(f"{data_dir}/findings.csv")
    return assets, findings


def join_findings_to_assets(findings, assets):
    """Attach the server details (importance, exposure, owner...) to each finding."""
    merged = findings.merge(
        assets.drop(columns=["hostname"]),  # findings already has hostname, so drop the duplicate
        on="asset_id",                       # join key: same asset_id
        how="left",                          # keep every finding, even with no matching server
    )
    # Matched a server in the inventory?
    merged["in_inventory"] = merged["criticality"].notna()
    return merged


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
CRITICALITY_POINTS = {"Critical": 15, "High": 10, "Medium": 5, "Low": 0}
REGULATED = {"FERPA", "HIPAA", "PCI", "CUI"}


def score_finding(row):
    """Return (score 0-100, priority P1-P4, reason) for one finding."""
    points = 0
    reasons = []

    # 1. Severity: CVSS x 4
    cvss_points = row["cvss"] * 4
    points += cvss_points
    reasons.append(f"CVSS {row['cvss']} (+{cvss_points:g})")

    # 2. Actively exploited (CISA KEV)
    if row["kev"] == "Yes":
        points += 25
        reasons.append("Known exploited, CISA KEV (+25)")

    # 3. Likelihood of exploitation (EPSS)
    if row["epss"] >= 0.5:
        points += 10
        reasons.append(f"EPSS {row['epss']} (+10)")
    elif row["epss"] >= 0.1:
        points += 5
        reasons.append(f"EPSS {row['epss']} (+5)")

    # 4. Asset criticality (unknown asset -> treat as High, to be safe)
    if pd.isna(row["criticality"]):
        points += 10
        reasons.append("Not in inventory, treated as High (+10)")
    elif CRITICALITY_POINTS[row["criticality"]] > 0:
        p = CRITICALITY_POINTS[row["criticality"]]
        points += p
        reasons.append(f"{row['criticality']} asset (+{p})")

    # 5. Internet exposure (unknown -> assume exposed)
    if row["internet_facing"] == "Yes":
        points += 10
        reasons.append("Internet-facing (+10)")
    elif pd.isna(row["internet_facing"]):
        points += 10
        reasons.append("Exposure unknown (+10)")

    # 6. Regulated data
    if row["data_classification"] in REGULATED:
        points += 5
        reasons.append(f"{row['data_classification']} data (+5)")

    score = min(100, round(points))
    if score >= 80:
        priority = "P1"
    elif score >= 60:
        priority = "P2"
    elif score >= 40:
        priority = "P3"
    else:
        priority = "P4"
    return score, priority, "; ".join(reasons)
