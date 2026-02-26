import argparse
import json
from pathlib import Path

from demoB.keyring import ensure_keyring


def main():
    args = parse_args()

    emisor = ensure_keyring(args.emisor_keyring, args.sig, args.kem)
    receptor = ensure_keyring(args.receptor_keyring, args.sig, args.kem)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "emisor_pub.json").write_text(
        json.dumps({"pk_sig": emisor["pk_sig"], "pk_kem": emisor["pk_kem"]}, indent=2),
        encoding="utf-8",
    )
    (out_dir / "receptor_pub.json").write_text(
        json.dumps({"pk_sig": receptor["pk_sig"], "pk_kem": receptor["pk_kem"]}, indent=2),
        encoding="utf-8",
    )
    print(f"OK: claves generadas en {out_dir}")


def parse_args():
    parser = argparse.ArgumentParser(description="Generación de claves para handshake híbrido")
    parser.add_argument("--sig", default="ML-DSA-65")
    parser.add_argument("--kem", default="ML-KEM-768")
    parser.add_argument("--out-dir", default="artifacts/keys")
    parser.add_argument("--emisor-keyring", default="artifacts/keys/emisor_keys.json")
    parser.add_argument("--receptor-keyring", default="artifacts/keys/receptor_keys.json")
    return parser.parse_args()


if __name__ == "__main__":
    main()
