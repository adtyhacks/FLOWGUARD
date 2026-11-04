"""Shared helpers for FLOWGUARD HTTP assessment scenarios."""

from __future__ import annotations

import time
from typing import Any

from ..client import FlowGuardClient
from ..config import FlowGuardConfig
from ..evidence import capture_evidence
from ..schemas import ApiResult, EvidenceRecord, ScenarioResult


class ScenarioBase:
    """Base utilities for bounded, local FLOWGUARD scenario execution."""

    scenario_id = ""
    scenario_name = ""
    expected_behavior = ""

    def __init__(
        self,
        client: FlowGuardClient | None = None,
        *,
        timeout: float = 5.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")
        self.client = client or FlowGuardClient(FlowGuardConfig.from_env())
        self.timeout = timeout
        self._started_at = 0.0
        self._evidence: list[EvidenceRecord] = []

    def _begin(self) -> None:
        self._started_at = time.perf_counter()
        self._evidence = []

    def _record(
        self,
        *,
        step: str,
        endpoint: str,
        request_method: str,
        result: ApiResult | None = None,
        request_payload: Any | None = None,
        request_headers: dict[str, Any] | None = None,
        observed_state: Any | None = None,
        response_payload: Any | None = None,
        response_status_code: int | None = None,
        error: str | None = None,
    ) -> None:
        if result is not None:
            response_payload = result.payload
            response_status_code = result.status_code
            error = result.error
        record = capture_evidence(
            scenario_id=self.scenario_id,
            endpoint=endpoint,
            request_method=request_method,
            request_payload=request_payload,
            request_headers=request_headers,
            response_payload=response_payload,
            response_status_code=response_status_code,
            observed_state={"step": step, **(observed_state or {})},
            error=error,
        )
        self._evidence.append(record)

    def _result(
        self,
        status: str,
        actual_behavior: str,
        *,
        error: str | None = None,
    ) -> ScenarioResult:
        elapsed_ms = int((time.perf_counter() - self._started_at) * 1000)
        return ScenarioResult(
            scenario_id=self.scenario_id,
            scenario_name=self.scenario_name,
            status=status,
            expected_behavior=self.expected_behavior,
            actual_behavior=actual_behavior,
            evidence=list(self._evidence),
            error=error,
            duration_ms=elapsed_ms,
        )


class _TimedAuthClient:
    """Bind the scenario timeout to auth-manager HTTP operations."""

    def __init__(self, client: FlowGuardClient, timeout: float) -> None:
        self._client = client
        self._timeout = timeout

    def register_user(self, username: str, email: str, password: str, *, mode: str | None = None) -> ApiResult:
        return self._client.post(
            "/auth/register",
            mode=mode,
            json={"username": username, "email": email, "password": password},
            timeout=self._timeout,
        )

    def login_user(self, username: str, password: str, *, mode: str | None = None) -> ApiResult:
        return self._client.post(
            "/auth/login",
            mode=mode,
            json={"username": username, "password": password},
            timeout=self._timeout,
        )

    def post(
        self,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        mode: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> ApiResult:
        return self._client.post(
            path,
            json=json,
            mode=mode,
            headers=headers,
            timeout=self._timeout if timeout is None else timeout,
        )
