import math
import os
from typing import Iterable

import pandas as pd
from scipy import stats

OUT_CSV = "artifacts/csv/statistical_analysis.csv"


def _load_if_exists(path: str):
    if not os.path.exists(path):
        return None
    return pd.read_csv(path)


def _family_label(value) -> str:
    if not isinstance(value, str):
        return "OTHER"
    upper = value.upper()
    if "SPHINCS" in upper:
        return "SPHINCS"
    if "ML-DSA" in upper:
        return "ML-DSA"
    return "OTHER"


def _ci95(values: Iterable[float]):
    vals = pd.Series(values, dtype="float64").dropna()
    n = len(vals)
    if n == 0:
        return float("nan"), float("nan"), float("nan"), float("nan")
    mean = float(vals.mean())
    std = float(vals.std(ddof=1)) if n > 1 else 0.0
    margin = 1.96 * (std / math.sqrt(n)) if n > 1 else 0.0
    return mean, std, mean - margin, mean + margin


def _analyze_metric(df: pd.DataFrame, metric_col: str, family_col: str, dataset_name: str):
    rows = []

    if metric_col not in df.columns or family_col not in df.columns:
        return rows

    values = pd.to_numeric(df[metric_col], errors="coerce")
    families = df[family_col].apply(_family_label)
    data = pd.DataFrame({"family": families, "value": values}).dropna(subset=["value"])

    mldsa_vals = data.loc[data["family"] == "ML-DSA", "value"]
    sphincs_vals = data.loc[data["family"] == "SPHINCS", "value"]

    for fam_name, fam_vals in (("ML-DSA", mldsa_vals), ("SPHINCS", sphincs_vals)):
        mean, std, ci_low, ci_high = _ci95(fam_vals)
        rows.append(
            {
                "dataset": dataset_name,
                "metric": metric_col,
                "family": fam_name,
                "n": int(len(fam_vals)),
                "mean": mean,
                "std": std,
                "ci95_low": ci_low,
                "ci95_high": ci_high,
                "mann_whitney_u": float("nan"),
                "mann_whitney_p_value": float("nan"),
            }
        )

    if len(mldsa_vals) > 0 and len(sphincs_vals) > 0:
        u_stat, p_value = stats.mannwhitneyu(mldsa_vals, sphincs_vals, alternative="two-sided")
        rows.append(
            {
                "dataset": dataset_name,
                "metric": metric_col,
                "family": "ML-DSA_vs_SPHINCS",
                "n": int(len(mldsa_vals) + len(sphincs_vals)),
                "mean": float("nan"),
                "std": float("nan"),
                "ci95_low": float("nan"),
                "ci95_high": float("nan"),
                "mann_whitney_u": float(u_stat),
                "mann_whitney_p_value": float(p_value),
            }
        )

    return rows


def main():
    os.makedirs("artifacts/csv", exist_ok=True)

    datasets = [
        (
            "artifacts/csv/sender_metrics.csv",
            "alg_family",
            ["sign_time_ms", "rtt_ms", "stanza_bytes", "sig_b64_bytes"],
            "xmpp_signature_sender",
        ),
        (
            "artifacts/csv/receiver_metrics.csv",
            "alg",
            ["verify_time_ms", "stanza_bytes"],
            "xmpp_signature_receiver",
        ),
        (
            "artifacts/csv/kem_signed_sender_metrics.csv",
            "sig_alg",
            ["kem_keygen_ms", "sign_time_ms", "decaps_time_ms", "sender_total_ms", "hello_bytes", "response_bytes"],
            "hybrid_local_sender",
        ),
        (
            "artifacts/csv/kem_signed_receiver_metrics.csv",
            "sig_alg",
            ["verify_time_ms", "encaps_time_ms", "receiver_total_ms", "hello_bytes", "response_bytes"],
            "hybrid_local_receiver",
        ),
        (
            "artifacts/csv/hybrid_xmpp_sender_metrics.csv",
            "alg_family",
            ["kem_keygen_time_ms", "sign_time_ms", "decaps_time_ms", "rtt_ms", "hello_stanza_bytes", "response_stanza_bytes"],
            "hybrid_xmpp_sender",
        ),
        (
            "artifacts/csv/hybrid_xmpp_receiver_metrics.csv",
            "sig_alg",
            ["verify_time_ms", "encaps_time_ms", "receiver_total_ms", "hello_stanza_bytes", "response_stanza_bytes"],
            "hybrid_xmpp_receiver",
        ),
    ]

    rows = []
    for csv_path, family_col, metrics, dataset_name in datasets:
        df = _load_if_exists(csv_path)
        if df is None:
            continue
        for metric_col in metrics:
            rows += _analyze_metric(df, metric_col, family_col, dataset_name)

    out = pd.DataFrame(rows)
    out.to_csv(OUT_CSV, index=False)
    print("Saved:", OUT_CSV)
    print(out)


if __name__ == "__main__":
    main()
