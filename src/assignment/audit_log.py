"""Audit log cho pipeline CP3."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from guardrails.output_guardrails import content_filter


def default_audit_log_path() -> str:
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogPlugin:
    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(
        self,
        *,
        user_id: str,
        text: str,
        request_id: str | None = None,
    ):
        key = request_id or user_id

        if key in self._open:
            raise ValueError(f"Request đang được xử lý: {key}")

        self._open[key] = {
            "request_id": key,
            "user_id": user_id,
            "input": content_filter(text)["redacted"],
            "started_at": utc_now_iso(),
            "_start_time": time.perf_counter(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        key = request_id or user_id

        if key not in self._open:
            raise ValueError(f"Chưa ghi input cho request: {key}")

        if self._open[key]["user_id"] != user_id:
            raise ValueError("User không khớp với request")

        entry = self._open.pop(key)
        start_time = entry.pop("_start_time")

        entry.update({
            "output": content_filter(text)["redacted"],
            "blocked": blocked,
            "layer": layer,
            "finished_at": utc_now_iso(),
            "latency_ms": round(
                (time.perf_counter() - start_time) * 1000,
                3,
            ),
        })

        self.logs.append(entry)

    def export_json(self, filepath: str | None = None):
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )