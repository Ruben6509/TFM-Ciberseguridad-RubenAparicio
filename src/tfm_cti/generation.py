from __future__ import annotations

import json
from typing import Any
from haystack import component
from haystack.components.generators.chat import OpenAIChatGenerator
from haystack.dataclasses import ChatMessage
from haystack.utils import Secret
from jsonschema import validate


# Generador local con salida JSON estructurada
@component
class StructuredLMStudioGenerator:

    def __init__(self, config: dict[str, Any]) -> None:
        generation = config["generation"]
        self.generation = generation
        self.generator = OpenAIChatGenerator(
            api_key=Secret.from_token("lm-studio"), api_base_url=generation["endpoint"],
            model=generation["model"],
        )

    @component.output_types(parsed=dict, raw_text=str, meta=dict, request_contract=dict)
    def run(self, messages: list[ChatMessage], schema: dict[str, Any], schema_name: str) -> dict[str, Any]:
        # Parámetros enviados a LM Studio
        kwargs = {
            "temperature": self.generation["temperature"], "top_p": self.generation["top_p"],
            "max_tokens": self.generation["max_tokens"], "tool_choice": self.generation["tool_choice"],
            "response_format": {"type": "json_schema", "json_schema": {
                "name": schema_name, "strict": True, "schema": schema,
            }},
            "extra_body": {
                "top_k": self.generation["top_k"],
                "reasoning_effort": self.generation["reasoning_effort"],
            },
        }
        # Generación y validación
        reply = self.generator.run(messages=messages, generation_kwargs=kwargs)["replies"][0]
        parsed = json.loads(reply.text)
        validate(instance=parsed, schema=schema)
        contract = {
            "model": self.generation["model"], "temperature": kwargs["temperature"],
            "top_p": kwargs["top_p"], "top_k": kwargs["extra_body"]["top_k"],
            "max_tokens": kwargs["max_tokens"],
            "reasoning_effort": kwargs["extra_body"]["reasoning_effort"],
            "tool_choice": kwargs["tool_choice"], "response_format": "json_schema/strict",
        }
        return {"parsed": parsed, "raw_text": reply.text, "meta": reply.meta, "request_contract": contract}
