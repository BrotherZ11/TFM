import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def p95(series: pd.Series) -> float:
    return float(series.quantile(0.95))


def ci95_half_width(series: pd.Series) -> float:
    n = len(series)
    if n < 2:
        return float("nan")
    return 1.96 * float(series.std(ddof=1)) / (n ** 0.5)


def summarize(df: pd.DataFrame, group_col: str, metric_col: str) -> pd.DataFrame:
    d = df[[group_col, metric_col]].dropna()
    g = d.groupby(group_col)[metric_col]
    out = pd.DataFrame(
        {
            "n": g.count(),
            "mean": g.mean(),
            "median": g.median(),
            "std": g.std(ddof=1),
            "p95": g.apply(p95),
            "ci95_half_width": g.apply(ci95_half_width),
        }
    ).reset_index()
    out.insert(1, "metric", metric_col)
    return out


def mann_whitney(df: pd.DataFrame, metric_col: str, group_col: str = "sig_alg") -> dict:
    d = df[[group_col, metric_col]].dropna()
    groups = sorted(d[group_col].unique())
    if len(groups) != 2:
        return {"metric": metric_col, "group_a": None, "group_b": None, "u_stat": float("nan"), "p_value": float("nan")}

    a_vals = d[d[group_col] == groups[0]][metric_col].values
    b_vals = d[d[group_col] == groups[1]][metric_col].values
    try:
        from scipy.stats import mannwhitneyu
        stat = mannwhitneyu(a_vals, b_vals, alternative="two-sided")
        u_stat = float(stat.statistic)
        p_val = float(stat.pvalue)
    except Exception:
        u_stat = float("nan")
        p_val = float("nan")
    return {
        "metric": metric_col,
        "group_a": groups[0],
        "group_b": groups[1],
        "u_stat": u_stat,
        "p_value": p_val,
    }


def save_boxplot(df: pd.DataFrame, metric: str, out_path: Path):
    d = df[["sig_alg", metric]].dropna()
    groups = sorted(d["sig_alg"].unique())
    if len(groups) < 1:
        return
    series = [d[d["sig_alg"] == g][metric].values for g in groups]
    plt.figure(figsize=(6, 4))
    plt.boxplot(series, labels=groups, showfliers=True)
    plt.title(f"{metric} por algoritmo")
    plt.ylabel(metric)
    plt.grid(True, axis="y")
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=180)
    plt.close()


def main():
    parser = argparse.ArgumentParser(description="Resumen estadístico de Fase 4")
    parser.add_argument("--sender", default="artifacts/csv/handshake_sender.csv")
    parser.add_argument("--receiver", default="artifacts/csv/handshake_receiver.csv")
    parser.add_argument("--out-csv", default="artifacts/csv/phase4_summary.csv")
    parser.add_argument("--out-md", default="artifacts/reports/phase4_summary.md")
    parser.add_argument("--out-mw", default="artifacts/csv/phase4_mannwhitney.csv")
    parser.add_argument("--fig-dir", default="artifacts/figs/phase4")
    args = parser.parse_args()

    sender = pd.read_csv(args.sender)
    receiver = pd.read_csv(args.receiver)

    if "ok" in sender.columns:
        sender = sender[sender["ok"] == 1].copy()
    if "ok" in receiver.columns:
        receiver = receiver[receiver["ok"] == 1].copy()

    summaries = []
    mw_rows = []
    sender_metrics = ["kem_encap_ms", "sign_init_ms", "verify_reply_ms", "sign_final_ms", "rtt_ms", "stanza_init_bytes"]
    receiver_metrics = ["verify_init_ms", "decap_ms", "sign_reply_ms", "stanza_reply_bytes"]

    for m in sender_metrics:
        if m in sender.columns:
            summaries.append(summarize(sender, "sig_alg", m))
            mw_rows.append(mann_whitney(sender, m))
            save_boxplot(sender, m, Path(args.fig_dir) / f"sender_{m}.png")
    for m in receiver_metrics:
        if m in receiver.columns:
            summaries.append(summarize(receiver, "sig_alg", m))
            mw_rows.append(mann_whitney(receiver, m))
            save_boxplot(receiver, m, Path(args.fig_dir) / f"receiver_{m}.png")

    if not summaries:
        raise RuntimeError("No hay métricas disponibles para resumir")

    out_df = pd.concat(summaries, ignore_index=True)
    mw_df = pd.DataFrame(mw_rows)

    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(out_csv, index=False)

    out_mw = Path(args.out_mw)
    out_mw.parent.mkdir(parents=True, exist_ok=True)
    mw_df.to_csv(out_mw, index=False)

    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# Resumen estadístico Fase 4\n\n")
        headers = list(out_df.columns)
        f.write("| " + " | ".join(headers) + " |\n")
        f.write("|" + "|".join(["---"] * len(headers)) + "|\n")
        for _, row in out_df.iterrows():
            vals = [str(row[h]) for h in headers]
            f.write("| " + " | ".join(vals) + " |\n")

        f.write("\n# Mann-Whitney U\n\n")
        headers2 = list(mw_df.columns)
        f.write("| " + " | ".join(headers2) + " |\n")
        f.write("|" + "|".join(["---"] * len(headers2)) + "|\n")
        for _, row in mw_df.iterrows():
            vals = [str(row[h]) for h in headers2]
            f.write("| " + " | ".join(vals) + " |\n")

    print(f"Resumen CSV: {out_csv}")
    print(f"Mann-Whitney CSV: {out_mw}")
    print(f"Resumen MD:  {out_md}")
    print(f"Figuras: {args.fig_dir}")


if __name__ == "__main__":
    main()
