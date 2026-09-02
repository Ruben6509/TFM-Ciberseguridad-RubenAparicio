from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any
import yaml


os.environ.setdefault("HAYSTACK_TELEMETRY_ENABLED", "false")
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")


# Rutas del proyecto
ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = ROOT
DEFAULT_CONFIG = ROOT / "config" / "runtime.yaml"


# Configuración
def load_config(path: Path = DEFAULT_CONFIG) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def resolve(path: str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else ROOT / candidate


# Lectura, escritura y hashes
def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
