import pytest

from experiments import latency_benchmark


@pytest.mark.parametrize("end_to_end", [False, True])
def test_latency_excludes_periodic_runtime_construction(monkeypatch, end_to_end):
    clock = 0
    builds = 0

    class Runtime:
        def evaluate(self, request):
            nonlocal clock
            clock += 10_000
            return True

        execute_request = evaluate

    def build(*args, **kwargs):
        nonlocal clock, builds
        clock += 1_000_000_000
        builds += 1
        return Runtime(), None, None

    monkeypatch.setattr(latency_benchmark, "build_guardian", build)
    monkeypatch.setattr(latency_benchmark.time, "perf_counter_ns", lambda: clock)
    invoker = latency_benchmark._end_to_end_invoker if end_to_end else latency_benchmark._decision_invoker
    result = latency_benchmark._measure_calls(*invoker("guardian_hardened"))
    assert builds == 3
    assert result["n"] == 200
    assert result["mean_ms"] == 0.01
    assert result["max_ms"] == 0.01


def test_latency_rejects_unknown_architecture():
    with pytest.raises(ValueError, match="unknown architecture"):
        latency_benchmark.measure("guardan_hardened")
