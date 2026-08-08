"""Deterministic generative property tests.

These serve the same role as property-based testing without requiring a particular generator library
at runtime. CI can additionally use Hypothesis when installed.
"""
import random
from guardian_runtime.factory import build_guardian
from guardian_runtime.types import ActionRequest


def _req(delta_v, nonce):
    return ActionRequest(subject='agent-1',session_id='p',tool='mission',action='maneuver',params={'delta_v':delta_v},purpose='operations',capability_id='cap-maneuver',nonce=nonce)


def test_random_out_of_envelope_maneuvers_never_execute():
    rng = random.Random(12345)
    for i in range(200):
        runtime, _, _ = build_guardian('mission', hardened=True)
        value = rng.choice([-1, 1]) * rng.uniform(5.1, 500)
        decision, result = runtime.execute_request(_req(value, f'n-{i}'))
        assert not decision.allowed
        assert result is None
        assert runtime.environment.state.cumulative_delta_v == 0


def test_random_in_capability_maneuvers_execute():
    rng = random.Random(54321)
    for i in range(100):
        runtime, _, _ = build_guardian('mission', hardened=True)
        value = rng.uniform(-2.9, 2.9)
        decision, result = runtime.execute_request(_req(value, f'n-{i}'))
        assert decision.allowed and result and result.ok
