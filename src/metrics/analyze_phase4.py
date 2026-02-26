import argparse
from pathlib import Path

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


def main():
    parser = argparse.ArgumentParser(description="Resumen estadístico de Fase 4")
    parser.add_argument("--sender", default="artifacts/csv/handshake_sender.csv")
    parser.add_argument("--receiver", default="artifacts/csv/handshake_receiver.csv")
    parser.add_argument("--out-csv", default="artifacts/csv/phase4_summary.csv")
    parser.add_argument("--out-md", default="artifacts/reports/phase4_summary.md")
    args = parser.parse_args()

    sender = pd.read_csv(args.sender)
    receiver = pd.read_csv(args.receiver)

    if "ok" in sender.columns:
        sender = sender[sender["ok"] == 1].copy()
    if "ok" in receiver.columns:
        receiver = receiver[receiver["ok"] == 1].copy()

    summaries = []
    sender_metrics = ["kem_encap_ms", "sign_init_ms", "verify_reply_ms", "rtt_ms", "stanza_init_bytes"]
    receiver_metrics = ["verify_init_ms", "decap_ms", "sign_reply_ms", "stanza_reply_bytes"]

    for m in sender_metrics:
        if m in sender.columns:
            summaries.append(summarize(sender, "sig_alg", m))
    for m in receiver_metrics:
        if m in receiver.columns:
            summaries.append(summarize(receiver, "sig_alg", m))

    if not summaries:
        raise RuntimeError("No hay métricas disponibles para resumir")

    out_df = pd.concat(summaries, ignore_index=True)

    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(out_csv, index=False)

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

    print(f"Resumen CSV: {out_csv}")
    print(f"Resumen MD:  {out_md}")


if __name__ == "__main__":
    main()
