"""
plot_comparison.py — Genera gráficas comparativas entre criptografía clásica y PQC
a partir de los CSV producidos por crypto_comparison_bench.py.

Salida:
  artifacts/figs/comparison_sign_times.png   — boxplot tiempos de firma (escala log)
  artifacts/figs/comparison_sig_sizes.png    — barras tamaño firma y clave pública
  artifacts/figs/comparison_kem_times.png    — boxplot tiempos KEM (encaps + decaps)
  artifacts/figs/comparison_kem_sizes.png    — barras tamaño clave pública y ciphertext

Uso:
  PYTHONPATH=src python src/metrics/plot_comparison.py
"""

import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd

SIG_CSV = Path("artifacts/csv/sig_comparison_metrics.csv")
KEM_CSV = Path("artifacts/csv/kem_comparison_metrics.csv")
FIG_DIR = Path("artifacts/figs")

# Orden canónico de algoritmos en las gráficas
SIG_ORDER = [
    "RSA-2048",
    "ECDSA-P256",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SPHINCS+-SHA2-128s-simple",
    "SPHINCS+-SHA2-128f-simple",
]

KEM_ORDER = [
    "ECDH-P256",
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
]

# Colores por tipo
TYPE_COLORS = {"classical": "#9E9E9E", "pqc": "#2196F3"}
SPHINCS_COLOR = "#FF5722"   # destaca SPHINCS+ por su diferente perfil de rendimiento


def _alg_color(row_type: str, alg_name: str) -> str:
    if "SPHINCS" in alg_name:
        return SPHINCS_COLOR
    return TYPE_COLORS.get(row_type, "#2196F3")


def _load_sig() -> pd.DataFrame | None:
    if not SIG_CSV.exists():
        print(f"WARN: no existe {SIG_CSV} — ejecuta crypto_comparison_bench.py primero")
        return None
    df = pd.read_csv(SIG_CSV)
    # Filtrar solo algoritmos en el orden canónico (ignora posibles extras)
    df = df[df["alg_name"].isin(SIG_ORDER)].copy()
    df["alg_name"] = pd.Categorical(df["alg_name"], categories=SIG_ORDER, ordered=True)
    return df.sort_values("alg_name")


def _load_kem() -> pd.DataFrame | None:
    if not KEM_CSV.exists():
        print(f"WARN: no existe {KEM_CSV} — ejecuta crypto_comparison_bench.py primero")
        return None
    df = pd.read_csv(KEM_CSV)
    df = df[df["alg_name"].isin(KEM_ORDER)].copy()
    df["alg_name"] = pd.Categorical(df["alg_name"], categories=KEM_ORDER, ordered=True)
    return df.sort_values("alg_name")


# ─── Figura 1: tiempos de firma (boxplot, log) ────────────────────────────────

def plot_sign_times(df: pd.DataFrame):
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    algs        = SIG_ORDER
    type_map    = df.drop_duplicates("alg_name").set_index("alg_name")["alg_type"].to_dict()
    colors      = [_alg_color(type_map.get(a, "pqc"), a) for a in algs]

    for ax, metric, label in [
        (axes[0], "sign_time_ms",   "Tiempo de firma (ms)"),
        (axes[1], "verify_time_ms", "Tiempo de verificación (ms)"),
    ]:
        data = [df[df["alg_name"] == a][metric].dropna().values for a in algs]
        bp   = ax.boxplot(data, patch_artist=True, medianprops={"color": "black", "linewidth": 2})
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
        ax.set_yscale("log")
        ax.set_ylabel(label + " (escala log)")
        ax.set_xticks(range(1, len(algs) + 1))
        ax.set_xticklabels(algs, rotation=35, ha="right", fontsize=8)
        ax.grid(axis="y", linestyle="--", alpha=0.4)
        ax.set_title(label)

    legend_patches = [
        mpatches.Patch(color=TYPE_COLORS["classical"], label="Clásico"),
        mpatches.Patch(color=TYPE_COLORS["pqc"],       label="PQC – retículos (ML-DSA)"),
        mpatches.Patch(color=SPHINCS_COLOR,            label="PQC – hash (SPHINCS+)"),
    ]
    fig.legend(handles=legend_patches, loc="upper center", ncol=3, fontsize=9, bbox_to_anchor=(0.5, 1.01))
    fig.suptitle("Comparativa tiempos de firma y verificación — Clásico vs PQC", fontsize=11, fontweight="bold")
    plt.tight_layout()
    out = FIG_DIR / "comparison_sign_times.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Figura → {out}")


# ─── Figura 2: tamaños de firma y clave pública (barras) ─────────────────────

def plot_sig_sizes(df: pd.DataFrame):
    summary = (
        df.groupby("alg_name", observed=True)[["sig_bytes", "pk_bytes"]]
        .mean()
        .reindex(SIG_ORDER)
    )

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    type_map  = df.drop_duplicates("alg_name").set_index("alg_name")["alg_type"].to_dict()
    colors    = [_alg_color(type_map.get(a, "pqc"), a) for a in summary.index]
    x         = range(len(summary))

    for ax, col, ylabel, title in [
        (axes[0], "sig_bytes", "Bytes",  "Tamaño de firma (bytes)"),
        (axes[1], "pk_bytes",  "Bytes",  "Tamaño de clave pública (bytes)"),
    ]:
        values = summary[col].values
        bars   = ax.bar(x, values, color=colors)
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.set_xticks(list(x))
        ax.set_xticklabels(summary.index, rotation=35, ha="right", fontsize=8)
        ax.bar_label(bars, fmt="%.0f", fontsize=7, padding=2)
        ax.grid(axis="y", linestyle="--", alpha=0.4)

    legend_patches = [
        mpatches.Patch(color=TYPE_COLORS["classical"], label="Clásico"),
        mpatches.Patch(color=TYPE_COLORS["pqc"],       label="PQC – ML-DSA"),
        mpatches.Patch(color=SPHINCS_COLOR,            label="PQC – SPHINCS+"),
    ]
    fig.legend(handles=legend_patches, loc="upper center", ncol=3, fontsize=9, bbox_to_anchor=(0.5, 1.01))
    fig.suptitle("Overhead de tamaño — Firma y clave pública: Clásico vs PQC", fontsize=11, fontweight="bold")
    plt.tight_layout()
    out = FIG_DIR / "comparison_sig_sizes.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Figura → {out}")


# ─── Figura 3: tiempos KEM (boxplot) ─────────────────────────────────────────

def plot_kem_times(df: pd.DataFrame):
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    algs      = KEM_ORDER
    type_map  = df.drop_duplicates("alg_name").set_index("alg_name")["alg_type"].to_dict()
    colors    = [TYPE_COLORS.get(type_map.get(a, "pqc"), "#2196F3") for a in algs]

    for ax, metric, label in [
        (axes[0], "keygen_time_ms",  "Keygen (ms)"),
        (axes[1], "encaps_time_ms",  "Encapsulación (ms)"),
        (axes[2], "decaps_time_ms",  "Desencapsulación (ms)"),
    ]:
        data = [df[df["alg_name"] == a][metric].dropna().values for a in algs]
        bp   = ax.boxplot(data, patch_artist=True, medianprops={"color": "black", "linewidth": 2})
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
        ax.set_yscale("log")
        ax.set_ylabel(label + " (escala log)")
        ax.set_title(label)
        ax.set_xticks(range(1, len(algs) + 1))
        ax.set_xticklabels(algs, rotation=25, ha="right", fontsize=8)
        ax.grid(axis="y", linestyle="--", alpha=0.4)

    legend_patches = [
        mpatches.Patch(color=TYPE_COLORS["classical"], label="ECDH P-256 (clásico)"),
        mpatches.Patch(color=TYPE_COLORS["pqc"],       label="ML-KEM (PQC)"),
    ]
    fig.legend(handles=legend_patches, loc="upper center", ncol=2, fontsize=9, bbox_to_anchor=(0.5, 1.01))
    fig.suptitle("Comparativa tiempos KEM — ECDH P-256 vs ML-KEM", fontsize=11, fontweight="bold")
    plt.tight_layout()
    out = FIG_DIR / "comparison_kem_times.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Figura → {out}")


# ─── Figura 4: tamaños KEM (barras) ──────────────────────────────────────────

def plot_kem_sizes(df: pd.DataFrame):
    summary  = (
        df.groupby("alg_name", observed=True)[["pk_bytes", "ct_bytes"]]
        .mean()
        .reindex(KEM_ORDER)
    )

    fig, axes = plt.subplots(1, 2, figsize=(11, 5))
    type_map  = df.drop_duplicates("alg_name").set_index("alg_name")["alg_type"].to_dict()
    colors    = [TYPE_COLORS.get(type_map.get(a, "pqc"), "#2196F3") for a in summary.index]
    x         = range(len(summary))

    for ax, col, title in [
        (axes[0], "pk_bytes", "Tamaño de clave pública (bytes)"),
        (axes[1], "ct_bytes", "Tamaño de ciphertext / efímero (bytes)"),
    ]:
        values = summary[col].values
        bars   = ax.bar(x, values, color=colors)
        ax.set_title(title)
        ax.set_ylabel("Bytes")
        ax.set_xticks(list(x))
        ax.set_xticklabels(summary.index, rotation=20, ha="right", fontsize=9)
        ax.bar_label(bars, fmt="%.0f", fontsize=8, padding=2)
        ax.grid(axis="y", linestyle="--", alpha=0.4)

    legend_patches = [
        mpatches.Patch(color=TYPE_COLORS["classical"], label="ECDH P-256 (clásico)"),
        mpatches.Patch(color=TYPE_COLORS["pqc"],       label="ML-KEM (PQC)"),
    ]
    fig.legend(handles=legend_patches, loc="upper center", ncol=2, fontsize=9, bbox_to_anchor=(0.5, 1.01))
    fig.suptitle("Overhead de tamaño KEM — ECDH P-256 vs ML-KEM", fontsize=11, fontweight="bold")
    plt.tight_layout()
    out = FIG_DIR / "comparison_kem_sizes.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Figura → {out}")


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs(FIG_DIR, exist_ok=True)

    df_sig = _load_sig()
    if df_sig is not None and not df_sig.empty:
        plot_sign_times(df_sig)
        plot_sig_sizes(df_sig)
    else:
        print("Sin datos de firma — omitiendo figuras de firma.")

    df_kem = _load_kem()
    if df_kem is not None and not df_kem.empty:
        plot_kem_times(df_kem)
        plot_kem_sizes(df_kem)
    else:
        print("Sin datos KEM — omitiendo figuras KEM.")
