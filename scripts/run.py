from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "src"))

from tfm_cti.pipeline import CTIPipeline
from tfm_cti.settings import ROOT, write_json


ROUTES = {"T1": "none", "T2": "cve_exact", "T3": "attack_semantic", "T4": "cti_semantic"}


# Argumentos de entrada
def main() -> int:
    parser = argparse.ArgumentParser(description="Ejecuta una consulta DIRECT, B0 o R1")
    parser.add_argument("--task", choices=ROUTES, required=True)
    parser.add_argument("--variant", choices=["DIRECT", "B0", "R1"], required=True)
    parser.add_argument("--question", required=True)
    parser.add_argument("--query", help="Consulta de recuperación; por defecto se usa la pregunta")
    parser.add_argument("--evidence-file", type=Path, help="Texto primario para T1 o consultas con evidencia")
    parser.add_argument("--case-id", default="DEMO")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.task == "T1" and args.variant != "DIRECT":
        parser.error("T1 se ejecuta como DIRECT")

    # Preparación del caso
    evidence = args.evidence_file.read_text(encoding="utf-8") if args.evidence_file else ""
    if args.task == "T3" and not evidence:
        evidence = args.question
    case = {
        "case_id": args.case_id,
        "window_id": args.case_id,
        "task": args.task,
        "route": ROUTES[args.task],
        "query": args.query or args.question,
        "question": args.question,
        "primary_evidence": evidence,
    }
    # Ejecución y guardado del resultado
    result = CTIPipeline().run(case, args.variant)
    output = args.output or ROOT / "runs" / (
        datetime.now(timezone.utc).strftime("demo_%Y%m%dT%H%M%SZ") + ".json"
    )
    write_json(output, result)
    print(json.dumps(result["parsed"], ensure_ascii=False, indent=2))
    print(f"Resultado completo: {output}")
    return 0 if result["validation"]["technical_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
