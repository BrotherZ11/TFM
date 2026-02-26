import argparse
import csv
import random
from pathlib import Path


def build_plan(sig_algs: list[str], kem_alg: str, repetitions: int, seed: int) -> list[dict]:
    rnd = random.Random(seed)
    rows = []
    seq = 0
    for sig in sig_algs:
        for rep in range(1, repetitions + 1):
            seq += 1
            rows.append(
                {
                    "seq": seq,
                    "sig_alg": sig,
                    "kem_alg": kem_alg,
                    "rep": rep,
                }
            )
    rnd.shuffle(rows)
    for idx, row in enumerate(rows, start=1):
        row["seq"] = idx
    return rows


def main():
    parser = argparse.ArgumentParser(description="Genera plan experimental reproducible")
    parser.add_argument("--sig-algs", nargs="+", default=["ML-DSA-65", "SPHINCS+-SHA2-128s-simple"])
    parser.add_argument("--kem", default="ML-KEM-768")
    parser.add_argument("--repetitions", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default="artifacts/csv/experiment_plan.csv")
    args = parser.parse_args()

    rows = build_plan(args.sig_algs, args.kem, args.repetitions, args.seed)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["seq", "sig_alg", "kem_alg", "rep"])
        w.writeheader()
        w.writerows(rows)

    print(f"Plan generado: {out} ({len(rows)} filas)")


if __name__ == "__main__":
    main()
