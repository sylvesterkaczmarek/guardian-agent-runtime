from __future__ import annotations

from guardian_runtime.adversarial import ARCHITECTURES, attack_scenarios, run_attack_scenario

if __name__ == "__main__":
    for architecture in ARCHITECTURES:
        successes = [run_attack_scenario(architecture, case).attack_success for case in attack_scenarios()]
        print(f"{architecture}: {sum(successes)}/{len(successes)} attacks succeeded")
