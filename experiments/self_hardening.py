from __future__ import annotations

import json

from guardian_runtime.adversarial.hardening import run_self_hardening

if __name__ == "__main__":
    print(json.dumps(run_self_hardening(), indent=2, sort_keys=True))
