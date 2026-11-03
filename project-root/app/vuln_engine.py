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


def score_all(df):
    """Score every finding and add risk_score, priority, reason and rank columns."""
    df = df.copy()
    results = [score_finding(row) for _, row in df.iterrows()]
    df["risk_score"] = [r[0] for r in results]
    df["priority"] = [r[1] for r in results]
    df["reason"] = [r[2] for r in results]
    # 1 = most urgent. method="min": ties share the same rank
    df["cvss_rank"] = df["cvss"].rank(ascending=False, method="min").astype(int)
    df["risk_rank"] = df["risk_score"].rank(ascending=False, method="min").astype(int)
    return df


def run(data_dir):
    """Whole pipeline so far: load -> join -> score."""
    assets, findings = load_data(data_dir)
    merged = join_findings_to_assets(findings, assets)
    return track_remediation(score_all(merged))


# ---------------------------------------------------------------------------
# Remediation tracking
# ---------------------------------------------------------------------------
SLA_DAYS = {"P1": 7, "P2": 30, "P3": 60, "P4": 90}
OPEN_STATUSES = {"Open", "In Progress", "Risk Accepted", "Not Verified"}


def track_remediation(df, as_of=None):
    """Check tickets against scan evidence, then work out deadlines."""
    df = df.copy()
    first_seen = pd.to_datetime(df["first_seen"])
    last_seen = pd.to_datetime(df["last_seen"])
    asset_scan = pd.to_datetime(df["last_scan_date"])

    # Latest scan of each host: the inventory's scan date, or for unknown devices
    # the scanner's most recent sighting of that host
    host_latest = last_seen.groupby(df["hostname"]).transform("max")
    latest_scan = asset_scan.fillna(host_latest)

    # 1. Rescan validation: ticket says fixed, but the latest scan still found it
    still_seen = (df["ticket_status"] == "Remediated") & (last_seen >= latest_scan)
    df["status"] = df["ticket_status"].mask(still_seen, "Not Verified")
    df["is_open"] = df["status"].isin(OPEN_STATUSES)

    # 2. Deadlines: first detection + SLA days for the priority
    if as_of is None:
        as_of = max(last_seen.max(), asset_scan.max())  # "today" = date of the latest scan
    df["due_date"] = (first_seen + pd.to_timedelta(df["priority"].map(SLA_DAYS), unit="D")).dt.date
    days_left = (pd.to_datetime(df["due_date"]) - as_of).dt.days

    df["sla_state"] = "Within SLA"
    df.loc[days_left <= 7, "sla_state"] = "Due ≤7d"
    df.loc[days_left < 0, "sla_state"] = "Overdue"
    df.loc[df["status"] == "Risk Accepted", "sla_state"] = "Exception"
    df.loc[df["status"] == "Remediated", "sla_state"] = "Closed"
    df["days_overdue"] = (-days_left).clip(lower=0)
    df.loc[~df["is_open"], "days_overdue"] = 0
    return df
