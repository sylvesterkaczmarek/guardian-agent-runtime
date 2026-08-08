from __future__ import annotations

from guardian_runtime.adversarial import attack_scenarios, run_attack_scenario

if __name__ == "__main__":
    case = next(case for case in attack_scenarios() if case.name == "log_modification_attempt")
    for architecture in ("guardian_initial", "guardian_hardened"):
        result = run_attack_scenario(architecture, case)
        print(f"{architecture}: tampering detected={not result.attack_success}")
