from __future__ import annotations

from typing import Any
from jsonschema import validate


# Validación técnica de la respuesta
def validate_trial(
    case: dict[str, Any], schema: dict[str, Any], parsed: dict[str, Any], available_refs: list[str]
) -> dict[str, Any]:
    validate(instance=parsed, schema=schema)
    cited = parsed["evidence_refs"]
    checks = {
        "case_id": parsed["case_id"] == case["case_id"],
        "references_known": all(ref in available_refs for ref in cited),
        "references_unique": len(cited) == len(set(cited)),
        "evidence_or_abstention": bool(cited) or parsed["abstained"],
        "abstention_consistent": (
            parsed["abstained"] and bool(parsed["abstention_reason"])
        ) or (not parsed["abstained"] and parsed["abstention_reason"] is None),
    }
    return {"checks": checks, "technical_success": all(checks.values())}
