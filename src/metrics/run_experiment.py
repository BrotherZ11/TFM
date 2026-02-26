import argparse
import csv
import os
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Orquestador de ejecuciones de handshake según plan")
    parser.add_argument("--plan", default="artifacts/csv/experiment_plan.csv")
    parser.add_argument("--python", default="python")
    parser.add_argument("--host", default="10.255.255.254")
    parser.add_argument("--port", default="5222")
    parser.add_argument("--jid-sender", default="emisor@localhost")
    parser.add_argument("--jid-receiver", default="receptor@localhost")
    parser.add_argument("--password", default="123")
    parser.add_argument("--execute", action="store_true", help="Ejecuta comandos; por defecto solo imprime runbook")
    args = parser.parse_args()

    plan_path = Path(args.plan)
    if not plan_path.exists():
        raise FileNotFoundError(plan_path)

    rows = list(csv.DictReader(plan_path.open("r", encoding="utf-8")))
    print(f"Plan cargado: {len(rows)} ejecuciones")

    for row in rows:
        sig_alg = row["sig_alg"]
        kem_alg = row["kem_alg"]
        seq = row["seq"]

        receiver_cmd = [
            args.python,
            "src/demoB/receptor_hybrid.py",
            "--jid", args.jid_receiver,
            "--password", args.password,
            "--sig", sig_alg,
            "--kem", kem_alg,
            "--host", args.host,
            "--port", args.port,
        ]
        sender_cmd = [
            args.python,
            "src/demoB/emisor_hybrid.py",
            "--jid", args.jid_sender,
            "--password", args.password,
            "--recipient", args.jid_receiver,
            "--sig", sig_alg,
            "--kem", kem_alg,
            "--host", args.host,
            "--port", args.port,
        ]

        print(f"\n[{seq}] sig={sig_alg} kem={kem_alg}")
        print("  receptor:", " ".join(receiver_cmd))
        print("  emisor:  ", " ".join(sender_cmd))

        if args.execute:
            env = os.environ.copy()
            env["PYTHONPATH"] = "src" if not env.get("PYTHONPATH") else f"src:{env['PYTHONPATH']}"
            receiver_proc = subprocess.Popen(receiver_cmd, env=env)
            time.sleep(1.0)
            sender_rc = subprocess.run(sender_cmd, check=False, env=env).returncode
            time.sleep(1.0)
            receiver_proc.terminate()
            try:
                receiver_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                receiver_proc.kill()
            if sender_rc != 0:
                print(f"WARNING: emisor retornó {sender_rc}")

    print("Runbook finalizado")


if __name__ == "__main__":
    main()
