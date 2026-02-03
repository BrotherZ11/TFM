import pandas as pd
import matplotlib.pyplot as plt

SENDER_CSV = "sender_metrics.csv"
RECEIVER_CSV = "receiver_metrics.csv"


def alg_family_from_algname(alg_name: str) -> str:
    if not isinstance(alg_name, str):
        return "UNKNOWN"
    if alg_name.startswith("SPHINCS+"):
        return "SPHINCS"
    if alg_name.startswith("ML-DSA"):
        return "ML-DSA"
    return "OTHER"


def boxplot_by_group(df, group_col, value_col, title, ylabel, out_png):
    df2 = df.dropna(subset=[value_col]).copy()
    groups = list(df2[group_col].unique())
    data = [df2[df2[group_col] == g][value_col].values for g in groups]

    plt.figure()
    # Matplotlib 3.9+: tick_labels en lugar de labels
    plt.boxplot(data, tick_labels=groups, showfliers=True)
    plt.title(title)
    plt.ylabel(ylabel)
    plt.grid(True, axis="y")
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)
    plt.close()
    print("Saved:", out_png)


def bar_mean_by_group(df, group_col, value_col, title, ylabel, out_png):
    means = df.groupby(group_col)[value_col].mean(numeric_only=True).sort_index()

    plt.figure()
    means.plot(kind="bar")
    plt.title(title)
    plt.ylabel(ylabel)
    plt.grid(True, axis="y")
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)
    plt.close()
    print("Saved:", out_png)


def main():
    sender = pd.read_csv(SENDER_CSV)
    receiver = pd.read_csv(RECEIVER_CSV)

    # Asegurar columna "alg_family" en receiver derivándola desde "alg"
    if "alg_family" not in receiver.columns:
        receiver["alg_family"] = receiver["alg"].apply(alg_family_from_algname)

    # Boxplots: tiempos + RTT
    boxplot_by_group(sender, "alg_family", "sign_time_ms",
                     "Tiempo de firma (ms) por algoritmo", "ms", "box_sign_time_ms.png")

    boxplot_by_group(receiver, "alg_family", "verify_time_ms",
                     "Tiempo de verificación (ms) por algoritmo", "ms", "box_verify_time_ms.png")

    boxplot_by_group(sender, "alg_family", "rtt_ms",
                     "RTT (ms) por algoritmo (XEP-0184 receipts)", "ms", "box_rtt_ms.png")

    # Barras: tamaños medios
    bar_mean_by_group(sender, "alg_family", "stanza_bytes",
                      "Tamaño medio de stanza enviada (bytes)", "bytes", "bar_stanza_bytes_sender.png")

    bar_mean_by_group(receiver, "alg_family", "stanza_bytes",
                      "Tamaño medio de stanza recibida (bytes)", "bytes", "bar_stanza_bytes_receiver.png")

    # Extra: tamaños de firma/pk (b64)
    bar_mean_by_group(sender, "alg_family", "sig_b64_bytes",
                      "Tamaño medio de firma b64 (bytes)", "bytes", "bar_sig_b64_bytes.png")

    bar_mean_by_group(sender, "alg_family", "pk_b64_bytes",
                      "Tamaño medio de pk b64 (bytes)", "bytes", "bar_pk_b64_bytes.png")


if __name__ == "__main__":
    main()
