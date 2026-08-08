import io
import json
import logging

from guardian_runtime.factory import build_guardian
from guardian_runtime.telemetry import JsonEventFormatter
from guardian_runtime.types import ActionRequest


def test_mediated_execution_emits_structured_operational_log_without_params():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonEventFormatter())
    logger = logging.getLogger("guardian-runtime-test")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)

    runtime, _, _ = build_guardian("mission", hardened=True)
    runtime.logger = logger
    request = ActionRequest(
        subject="agent-1",
        session_id="log-test",
        tool="mission",
        action="observe_telemetry",
        purpose="operations",
        capability_id="cap-observe",
        nonce="log-1",
        params={"should_not_appear": "MOCK-SENSITIVE-VALUE"},
    )
    decision, result = runtime.execute_request(request)
    assert not decision.allowed
    assert result is None

    payload = json.loads(stream.getvalue())
    assert payload["event"]["name"] == "guardian.denial"
    assert payload["event"]["allowed"] is False
    assert "MOCK-SENSITIVE-VALUE" not in stream.getvalue()
