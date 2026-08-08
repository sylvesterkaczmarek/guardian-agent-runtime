import random
from guardian_runtime.factory import build_guardian
from guardian_runtime.types import ActionRequest


def test_random_action_sequences_preserve_hard_delta_v_limit():
    rng = random.Random(7)
    runtime, _, _ = build_guardian('mission', hardened=True)
    for i in range(10):
        value = rng.uniform(-3, 3)
        r = ActionRequest(subject='agent-1',session_id='seq',tool='mission',action='maneuver',params={'delta_v':value},purpose='operations',capability_id='cap-maneuver',nonce=f'n{i}')
        runtime.execute_request(r)
    assert runtime.environment.state.cumulative_delta_v <= 30
