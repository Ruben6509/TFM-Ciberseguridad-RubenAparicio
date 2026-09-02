from __future__ import annotations

from typing import Any


# Campos comunes de todas las respuestas
COMMON = {
    "case_id": {"type": "string"},
    "evidence_refs": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
    "abstained": {"type": "boolean"},
    "abstention_reason": {"type": ["string", "null"]},
}


# Construcción de los esquemas
def _schema(properties: dict[str, Any]) -> dict[str, Any]:
    merged = {**properties, **COMMON}
    return {
        "type": "object", "properties": merged, "required": list(merged),
        "additionalProperties": False,
    }


# Esquemas de salida por tarea
SCHEMAS = {
    "T1": _schema({
        "window_id": {"type": "string"},
        "iocs": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "type": {"enum": ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "cve"]},
                "value": {"type": "string"},
            },
            "required": ["type", "value"],
        }},
    }),
    "T2": _schema({
        "cve_id": {"type": "string"},
        "classification": {"enum": ["real", "absent_from_snapshot", "unknown"]},
        "snapshot": {"type": ["string", "null"]},
    }),
    "T3": _schema({
        "mappings": {"type": "array", "maxItems": 3, "items": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "attack_id": {"type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"},
                "attack_name": {"type": "string"},
                "is_subtechnique": {"type": "boolean"},
                "justification": {"type": "string"},
            },
            "required": ["attack_id", "attack_name", "is_subtechnique", "justification"],
        }},
    }),
    "T4": _schema({
        "answer": {"type": ["string", "null"]},
        "supporting_quotes": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "properties": {"reference": {"type": "string"}, "quote": {"type": "string"}},
            "required": ["reference", "quote"],
        }},
    }),
}


# Instrucciones por tarea
TASK_INSTRUCTIONS = {
    "T1": "Extrae los IoC explícitos y normaliza su tipo y valor",
    "T2": "Determina si el identificador CVE existe en la instantánea local",
    "T3": "Asigna el comportamiento a la técnica o subtécnica ATT&CK más específica respaldada",
    "T4": "Responde a la pregunta y aporta citas textuales de la evidencia utilizada",
}
