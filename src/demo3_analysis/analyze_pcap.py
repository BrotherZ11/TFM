"""
analyze_pcap.py — Extrae métricas de red (capa TCP/IP) de los archivos .pcapng/.pcap
generados durante los experimentos del TFM para cuantificar el overhead de tráfico
de cada escenario PQC.

Salida:
  artifacts/csv/pcap_network_metrics.csv   (una fila por archivo pcap)
  artifacts/figs/pcap_network_comparison.png

Uso:
  PYTHONPATH=src python src/demo3_analysis/analyze_pcap.py
"""

import csv
import os
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from scapy.all import rdpcap, TCP, IP

PCAP_DIR = Path("artifacts/pcap")
OUT_CSV  = Path("artifacts/csv/pcap_network_metrics.csv")
OUT_FIG  = Path("artifacts/figs/pcap_network_comparison.png")

XMPP_PORT = 5222

# Etiquetas legibles por nombre de archivo (sin extensión)
SCENARIO_LABELS = {
    "demoA_mldsa":                 "Demo1 – ML-DSA",
    "demoA_sphnics":               "Demo1 – SPHINCS+",
    "demoA_wsl_clear":             "Demo1 – Texto claro",
    "demo1_signatures_xmpp":       "Demo1 – Firmas XMPP",
    "demo2a_local_optional":       "Demo2A – Local",
    "demo2b_hybrid_xmpp_cert":     "Demo2B – Cert",
    "demo2b_hybrid_xmpp_cert_509": "Demo2B – Cert X.509",
    "demo2c_hybrid_xmpp_qr":       "Demo2C – QR",
}

CSV_FIELDS = [
    "pcap_file", "scenario", "filter",
    "total_packets", "total_ip_bytes", "total_tcp_payload_bytes",
    "num_tcp_segments", "num_large_segments", "num_streams",
    "session_duration_ms", "mean_payload_bytes", "max_payload_bytes",
    "retransmissions",
]


def _filter_packets(packets):
    """Devuelve (paquetes_filtrados, nota_filtro).
    Preferencia: puerto XMPP 5222; fallback: todo TCP."""
    xmpp = [p for p in packets
             if p.haslayer(TCP) and (p[TCP].dport == XMPP_PORT or p[TCP].sport == XMPP_PORT)]
    if xmpp:
        return xmpp, f"xmpp:{XMPP_PORT}"
    tcp_all = [p for p in packets if p.haslayer(TCP)]
    return tcp_all, "tcp_all"


def _tcp_payload_sizes(packets) -> list:
    """Tamaños de payload TCP > 0 bytes."""
    sizes = []
    for pkt in packets:
        if pkt.haslayer(TCP):
            pl = len(bytes(pkt[TCP].payload))
            if pl > 0:
                sizes.append(pl)
    return sizes


def analyze_pcap(path: Path) -> dict | None:
    stem     = path.stem
    scenario = SCENARIO_LABELS.get(stem, stem)

    try:
        packets = rdpcap(str(path))
    except Exception as exc:
        print(f"  WARN {path.name}: {exc}")
        return None

    use_pkts, filter_note = _filter_packets(packets)
    if not use_pkts:
        print(f"  WARN {path.name}: sin paquetes TCP")
        return None

    timestamps     = [float(p.time) for p in use_pkts]
    session_ms     = (max(timestamps) - min(timestamps)) * 1000.0
    total_ip_bytes = sum(len(bytes(p)) for p in use_pkts if p.haslayer(IP))

    payload_sizes      = _tcp_payload_sizes(use_pkts)
    total_payload      = sum(payload_sizes)
    num_segments       = len(payload_sizes)
    num_large          = sum(1 for s in payload_sizes if s > 1460)
    max_payload        = max(payload_sizes) if payload_sizes else 0
    mean_payload       = statistics.fmean(payload_sizes) if payload_sizes else 0.0

    # Streams TCP únicos (src_ip, src_port, dst_ip, dst_port)
    streams: set = set()
    seen_seqs: set = set()
    retransmissions   = 0
    for p in use_pkts:
        if p.haslayer(TCP) and p.haslayer(IP):
            streams.add((p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport))
            key = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport, p[TCP].seq)
            if key in seen_seqs:
                retransmissions += 1
            else:
                seen_seqs.add(key)

    print(
        f"  {path.name:<42} | {len(use_pkts):>5} pkts | "
        f"{total_ip_bytes / 1024:>8.1f} KB | "
        f"{num_large:>4} seg>1460B | "
        f"dur={session_ms:>8.0f} ms | {filter_note}"
    )

    return {
        "pcap_file":               path.name,
        "scenario":                scenario,
        "filter":                  filter_note,
        "total_packets":           len(use_pkts),
        "total_ip_bytes":          total_ip_bytes,
        "total_tcp_payload_bytes": total_payload,
        "num_tcp_segments":        num_segments,
        "num_large_segments":      num_large,
        "num_streams":             len(streams),
        "session_duration_ms":     round(session_ms, 2),
        "mean_payload_bytes":      round(mean_payload, 1),
        "max_payload_bytes":       max_payload,
        "retransmissions":         retransmissions,
    }


def save_csv(rows: list):
    os.makedirs(OUT_CSV.parent, exist_ok=True)
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"\nCSV → {OUT_CSV}")


def save_figure(rows: list):
    os.makedirs(OUT_FIG.parent, exist_ok=True)

    # Excluir capturas combinadas/redundantes: la captura conjunta Demo1 y la
    # captura WSL-completa no son comparables directamente con las individuales.
    EXCLUDE = {"demo1_signatures_xmpp", "demoA_wsl_clear"}
    rows = [r for r in rows if r["pcap_file"].split(".")[0] not in EXCLUDE]

    # Orden lógico: Demo1 PQC → Demo2A local → Demo2B/C XMPP
    ORDER = [
        "Demo1 – ML-DSA",
        "Demo1 – SPHINCS+",
        "Demo2A – Local",
        "Demo2B – Cert",
        "Demo2B – Cert X.509",
        "Demo2C – QR",
    ]
    rows = sorted(rows, key=lambda r: ORDER.index(r["scenario"]) if r["scenario"] in ORDER else 99)

    # Colores por grupo de experimento
    COLOR_MAP = {
        "Demo1 – ML-DSA":      "#1565C0",  # azul oscuro
        "Demo1 – SPHINCS+":    "#42A5F5",  # azul claro
        "Demo2A – Local":      "#6A1B9A",  # morado
        "Demo2B – Cert":       "#2E7D32",  # verde oscuro
        "Demo2B – Cert X.509": "#66BB6A",  # verde claro
        "Demo2C – QR":         "#A5D6A7",  # verde muy claro
    }

    scenarios  = [r["scenario"] for r in rows]
    ip_kb      = [r["total_ip_bytes"] / 1024 for r in rows]
    payload_kb = [r["total_tcp_payload_bytes"] / 1024 for r in rows]
    large_segs = [r["num_large_segments"] for r in rows]
    dur_s      = [r["session_duration_ms"] / 1000 for r in rows]
    retrans    = [r["retransmissions"] for r in rows]
    bar_colors = [COLOR_MAP.get(s, "#90A4AE") for s in scenarios]
    x          = list(range(len(rows)))

    fig, axes = plt.subplots(4, 1, figsize=(11, 15))

    def _bar(ax, values, ylabel, title, fmt="%.0f", suffix=""):
        bars = ax.bar(x, values, color=bar_colors)
        ax.set_title(title, fontsize=10)
        ax.set_ylabel(ylabel)
        ax.set_xticks(x)
        ax.set_xticklabels(scenarios, rotation=28, ha="right", fontsize=8)
        ax.bar_label(bars, labels=[f"{v:{fmt[2:]}}{suffix}" for v in values], fontsize=7, padding=2)
        ax.set_ylim(0, max(values) * 1.15)

    # Subplot 1: Bytes IP totales
    _bar(axes[0], ip_kb, "KB", "Tráfico IP total por escenario", fmt="%.0f", suffix=" KB")

    # Subplot 2: Payload TCP útil
    _bar(axes[1], payload_kb, "KB", "Payload TCP útil por escenario", fmt="%.0f", suffix=" KB")

    # Subplot 3: Segmentos TCP con payload > 1460 B (overhead de material PQC grande)
    _bar(axes[2], large_segs, "Nº segmentos",
         "Segmentos TCP con payload > 1460 bytes (indicador de stanzas PQC grandes)",
         fmt="%.0f")

    # Subplot 4: Duración de sesión TCP
    _bar(axes[3], dur_s, "Segundos", "Duración de sesión TCP", fmt="%.2f", suffix=" s")

    # Leyenda de grupos
    from matplotlib.patches import Patch
    legend_handles = [
        Patch(color="#1565C0", label="Demo1 — ML-DSA-65"),
        Patch(color="#42A5F5", label="Demo1 — SPHINCS+-128s"),
        Patch(color="#6A1B9A", label="Demo2A — Handshake local"),
        Patch(color="#2E7D32", label="Demo2B/C — Handshake XMPP"),
    ]
    fig.legend(handles=legend_handles, loc="upper right", fontsize=8,
               title="Familia / experimento", title_fontsize=8,
               framealpha=0.85, bbox_to_anchor=(0.99, 0.99))

    plt.suptitle("Análisis de tráfico de red — Comparativa por algoritmo PQC",
                 fontsize=12, fontweight="bold", y=1.01)
    plt.tight_layout()
    plt.savefig(OUT_FIG, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Figura → {OUT_FIG}")


if __name__ == "__main__":
    pcap_files = sorted(PCAP_DIR.glob("*.pcapng")) + sorted(PCAP_DIR.glob("*.pcap"))
    if not pcap_files:
        print(f"ERROR: no hay archivos pcap en {PCAP_DIR}")
        raise SystemExit(1)

    print(f"Analizando {len(pcap_files)} archivo(s) en {PCAP_DIR}/\n")
    rows = [row for path in pcap_files if (row := analyze_pcap(path)) is not None]

    if rows:
        save_csv(rows)
        save_figure(rows)
        print(f"\nFinalizado: {len(rows)}/{len(pcap_files)} archivos analizados.")
    else:
        print("No se obtuvieron métricas.")
