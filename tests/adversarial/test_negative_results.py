from experiments.negative_results import run_negative_results


def test_deliberate_negative_results_remain_visible():
    results = run_negative_results()
    assert results["policy_incompleteness"]["initial_proxy_bypass_succeeds"]
    assert results["hardening_overfit"]["known_secret_route_blocked"]
    assert results["hardening_overfit"]["network_route_still_bypasses"]
    assert results["hardening_overfit"]["actuator_route_still_bypasses"]
    assert results["utility_tradeoff"]["aggressive_policy_blocks_benign_network_task"]
    assert results["key_compromise"]["forged_guardian_signature_bypasses_hardened_policy"]
    assert results["compromised_tool"]["undeclared_tool_side_effect_escapes_guardian_model"]
