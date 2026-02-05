import os
import pandas as pd
import matplotlib.pyplot as plt

SENDER_CSV = "artifacts/csv/sender_metrics.csv"
RECEIVER_CSV = "artifacts/csv/receiver_metrics.csv"
FIGS_DIR = "artifacts/figs"


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
    # Crear directorio de figuras si no existe
    os.makedirs(FIGS_DIR, exist_ok=True)

    sender = pd.read_csv(SENDER_CSV)
    receiver = pd.read_csv(RECEIVER_CSV)

    # Asegurar columna "alg_family" en receiver
    if "alg_family" not in receiver.columns:
        receiver["alg_family"] = receiver["alg"].apply(alg_family_from_algname)

    # Boxplots
    boxplot_by_group(
        sender, "alg_family", "sign_time_ms",
        "Tiempo de firma (ms) por algoritmo", "ms",
        os.path.join(FIGS_DIR, "box_sign_time_ms.png")
    )

    boxplot_by_group(
        receiver, "alg_family", "verify_time_ms",
        "Tiempo de verificación (ms) por algoritmo", "ms",
        os.path.join(FIGS_DIR, "box_verify_time_ms.png")
    )

    boxplot_by_group(
        sender, "alg_family", "rtt_ms",
        "RTT (ms) por algoritmo (XEP-0184 receipts)", "ms",
        os.path.join(FIGS_DIR, "box_rtt_ms.png")
    )

    # Barras
    bar_mean_by_group(
        sender, "alg_family", "stanza_bytes",
        "Tamaño medio de stanza enviada (bytes)", "bytes",
        os.path.join(FIGS_DIR, "bar_stanza_bytes_sender.png")
    )

    bar_mean_by_group(
        receiver, "alg_family", "stanza_bytes",
        "Tamaño medio de stanza recibida (bytes)", "bytes",
        os.path.join(FIGS_DIR, "bar_stanza_bytes_receiver.png")
    )

    bar_mean_by_group(
        sender, "alg_family", "sig_b64_bytes",
        "Tamaño medio de firma b64 (bytes)", "bytes",
        os.path.join(FIGS_DIR, "bar_sig_b64_bytes.png")
    )

    bar_mean_by_group(
        sender, "alg_family", "pk_b64_bytes",
        "Tamaño medio de pk b64 (bytes)", "bytes",
        os.path.join(FIGS_DIR, "bar_pk_b64_bytes.png")
    )


if __name__ == "__main__":
    main()
