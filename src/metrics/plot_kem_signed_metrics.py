import os
import pandas as pd
import matplotlib.pyplot as plt

SENDER_CSV = "artifacts/csv/kem_signed_sender_metrics.csv"
RECEIVER_CSV = "artifacts/csv/kem_signed_receiver_metrics.csv"
FIGS_DIR = "artifacts/figs"


def boxplot_by_group(df, group_col, value_col, title, ylabel, out_png):
    df2 = df.dropna(subset=[value_col]).copy()
    groups = list(df2[group_col].unique())
    data = [df2[df2[group_col] == g][value_col].values for g in groups]

    plt.figure()
    plt.boxplot(data, labels=groups, showfliers=True)
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
    os.makedirs(FIGS_DIR, exist_ok=True)

    sender = pd.read_csv(SENDER_CSV)
    receiver = pd.read_csv(RECEIVER_CSV)

    # Boxplots de tiempos
    boxplot_by_group(
        sender,
        "sig_alg",
        "sign_time_ms",
        "Handshake híbrido: tiempo de firma por algoritmo",
        "ms",
        os.path.join(FIGS_DIR, "kem_box_sign_time_ms.png"),
    )

    boxplot_by_group(
        receiver,
        "sig_alg",
        "verify_time_ms",
        "Handshake híbrido: tiempo de verificación por algoritmo",
        "ms",
        os.path.join(FIGS_DIR, "kem_box_verify_time_ms.png"),
    )

    boxplot_by_group(
        receiver,
        "sig_alg",
        "encaps_time_ms",
        "ML-KEM: tiempo de encapsulación por algoritmo de firma",
        "ms",
        os.path.join(FIGS_DIR, "kem_box_encaps_time_ms.png"),
    )

    boxplot_by_group(
        sender,
        "sig_alg",
        "decaps_time_ms",
        "ML-KEM: tiempo de desacapsulación por algoritmo de firma",
        "ms",
        os.path.join(FIGS_DIR, "kem_box_decaps_time_ms.png"),
    )

    # Barras tamaño medio
    bar_mean_by_group(
        sender,
        "sig_alg",
        "hello_bytes",
        "Tamaño medio mensaje HELLO (bytes)",
        "bytes",
        os.path.join(FIGS_DIR, "kem_bar_hello_bytes.png"),
    )

    bar_mean_by_group(
        sender,
        "sig_alg",
        "response_bytes",
        "Tamaño medio mensaje RESPONSE (bytes)",
        "bytes",
        os.path.join(FIGS_DIR, "kem_bar_response_bytes.png"),
    )


if __name__ == "__main__":
    main()
