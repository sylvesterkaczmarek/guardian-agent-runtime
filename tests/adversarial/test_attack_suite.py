from guardian_runtime.adversarial import attack_scenarios, run_attack_scenario


def test_hardened_guardian_blocks_reference_attack_suite():
    results = [run_attack_scenario('guardian_hardened', case) for case in attack_scenarios()]
    assert not any(result.attack_success for result in results)


def test_initial_guardian_has_deliberate_proxy_bypass():
    results = {case.name: run_attack_scenario('guardian_initial', case) for case in attack_scenarios()}
    assert results['confused_deputy'].attack_success
    assert results['route_around_blocked_tool'].attack_success


def test_self_hardening_evaluates_generated_candidate_before_retention():
    from guardian_runtime.adversarial.hardening import run_self_hardening

    result = run_self_hardening()
    assert result["history"]
    history = result["history"][0]
    assert history["candidate_policy_matches_reviewed_policy"]
    assert history["retained"]
    assert result["remaining_bypasses"] == []
    assert result["benign_completion_after"] >= result["benign_completion_before"]
