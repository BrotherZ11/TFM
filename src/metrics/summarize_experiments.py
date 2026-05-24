import os
import pandas as pd

OUT_SUMMARY = "artifacts/csv/summary_experiments.csv"


def _load_if_exists(path: str):
    if not os.path.exists(path):
        return None
    return pd.read_csv(path)


def _summarize(df, group_col, columns, experiment_name):
    rows = []
    if df is None or group_col not in df.columns:
        return rows

    grouped = df.groupby(group_col)
    for group_name, group_df in grouped:
        row = {
            "experiment": experiment_name,
            "group": group_name,
            "n": len(group_df),
        }
        for c in columns:
            if c in group_df.columns:
                s = pd.to_numeric(group_df[c], errors="coerce")
                row[f"{c}_mean"] = s.mean()
                row[f"{c}_median"] = s.median()
                row[f"{c}_p95"] = s.quantile(0.95)
                row[f"{c}_std"] = s.std()
        rows.append(row)
    return rows


def main():
    os.makedirs("artifacts/csv", exist_ok=True)

    sender_sig = _load_if_exists("artifacts/csv/sender_metrics.csv")
    receiver_sig = _load_if_exists("artifacts/csv/receiver_metrics.csv")
    sender_kem_local = _load_if_exists("artifacts/csv/kem_signed_sender_metrics.csv")
    receiver_kem_local = _load_if_exists("artifacts/csv/kem_signed_receiver_metrics.csv")
    sender_kem_xmpp = _load_if_exists("artifacts/csv/hybrid_xmpp_sender_metrics.csv")
    receiver_kem_xmpp = _load_if_exists("artifacts/csv/hybrid_xmpp_receiver_metrics.csv")

    rows = []

    rows += _summarize(
        sender_sig,
        "alg_family",
        ["sig_keygen_time_ms", "sign_time_ms", "serialize_time_ms", "rtt_ms", "net_baseline_rtt_ms", "stanza_bytes", "sig_b64_bytes"],
        "xmpp_signature_sender",
    )
    rows += _summarize(
        receiver_sig,
        "alg",
        ["deserialize_time_ms", "verify_time_ms", "stanza_bytes", "mem_rss_kb"],
        "xmpp_signature_receiver",
    )

    rows += _summarize(
        sender_kem_local,
        "sig_alg",
        ["kem_keygen_ms", "sig_keygen_ms", "sign_time_ms", "decaps_time_ms", "sender_total_ms", "hello_bytes", "response_bytes", "kem_pk_bytes"],
        "hybrid_local_sender",
    )
    rows += _summarize(
        receiver_kem_local,
        "sig_alg",
        ["verify_time_ms", "encaps_time_ms", "receiver_total_ms", "hello_bytes", "response_bytes", "kem_pk_bytes", "kem_ct_bytes"],
        "hybrid_local_receiver",
    )

    rows += _summarize(
        sender_kem_xmpp,
        "alg_family",
        ["kem_keygen_time_ms", "sign_time_ms", "serialize_time_ms", "decaps_time_ms", "rtt_ms", "sender_total_ms", "hello_stanza_bytes", "response_stanza_bytes", "kem_pk_bytes"],
        "hybrid_xmpp_sender",
    )
    rows += _summarize(
        receiver_kem_xmpp,
        "sig_alg",
        ["deserialize_time_ms", "verify_time_ms", "encaps_time_ms", "receiver_total_ms", "hello_stanza_bytes", "response_stanza_bytes", "kem_pk_bytes", "kem_ct_bytes"],
        "hybrid_xmpp_receiver",
    )

    out = pd.DataFrame(rows)

    # Métricas derivadas: proporción de crypto sobre el RTT total
    sender_mask = out["experiment"].isin(["xmpp_signature_sender", "hybrid_xmpp_sender"])
    if "sign_time_ms_mean" in out.columns and "rtt_ms_mean" in out.columns:
        out.loc[sender_mask, "crypto_pct_of_rtt"] = (
            out.loc[sender_mask, "sign_time_ms_mean"] / out.loc[sender_mask, "rtt_ms_mean"] * 100
        ).round(1)

    # Overhead de stanza respecto al RTT de red base (Demo 1)
    sig_sender_mask = out["experiment"] == "xmpp_signature_sender"
    if "net_baseline_rtt_ms_mean" in out.columns and "rtt_ms_mean" in out.columns:
        out.loc[sig_sender_mask, "rtt_overhead_over_baseline_pct"] = (
            (out.loc[sig_sender_mask, "rtt_ms_mean"] - out.loc[sig_sender_mask, "net_baseline_rtt_ms_mean"])
            / out.loc[sig_sender_mask, "net_baseline_rtt_ms_mean"] * 100
        ).round(1)
    out.to_csv(OUT_SUMMARY, index=False)
    print("Saved:", OUT_SUMMARY)
    print(out)


if __name__ == "__main__":
    main()
