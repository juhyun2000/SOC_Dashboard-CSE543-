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
