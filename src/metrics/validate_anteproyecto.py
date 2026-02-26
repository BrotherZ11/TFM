import argparse
from pathlib import Path

REQUIRED_PATHS = [
    "docs/FASE1_diseno_protocolo_hibrido.md",
    "docs/FASE2_integracion_slixmpp.md",
    "docs/FASE3_sistema_metricas.md",
    "docs/FASE4_diseno_experimental.md",
    "docs/FASE5_analisis_final.md",
    "docs/CUMPLIMIENTO_ANTEPROYECTO.md",
    "src/protocol/hybrid_protocol.py",
    "src/demoA/emisor.py",
    "src/demoA/receptor.py",
    "src/demoA/emisor_bench.py",
    "src/demoA/receptor_bench.py",
    "src/demoB/emisor_hybrid.py",
    "src/demoB/receptor_hybrid.py",
    "src/demoB/setup_keys.py",
    "src/metrics/experiment_plan.py",
    "src/metrics/run_experiment.py",
    "src/metrics/analyze_phase4.py",
    "src/metrics/plot_metrics.py",
]

OPTIONAL_ARTIFACTS = [
    "artifacts/pcap",
    "artifacts/figs",
    "artifacts/csv",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Valida cobertura del anteproyecto")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    root = Path(args.root)
    missing = []

    print("== Verificación de rutas requeridas ==")
    for rel in REQUIRED_PATHS:
        p = root / rel
        ok = p.exists()
        print(f"[{ 'OK' if ok else 'MISS' }] {rel}")
        if not ok:
            missing.append(rel)

    print("\n== Verificación de artefactos opcionales (deseables) ==")
    for rel in OPTIONAL_ARTIFACTS:
        p = root / rel
        print(f"[{ 'OK' if p.exists() else 'WARN' }] {rel}")

    if missing:
        print("\nResultado: NO CUMPLE (faltan rutas requeridas)")
        return 1

    print("\nResultado: CUMPLE (estructura requerida presente)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
