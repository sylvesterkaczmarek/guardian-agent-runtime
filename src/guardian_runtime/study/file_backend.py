"""Run a synthetic integer workflow in a disposable directory.

`run_file_workflow(mode, target)` returns the command's acknowledgement, the
parent's independently observed file history, and the visible sample history.
The parent starts the file at 0. A child publishes each update by renaming a
closed file, signals only that a step finished, and waits for the parent's
receipt before continuing. The parent opens the state file before issuing each
receipt and reads it again after the child exits. A commit means a replacement
visible to another process on the same filesystem. The pilot does not measure
crash durability or changes between these synchronized reads.

Normal runs write 1 then the target (3 or 4). An acknowledged noop writes
nothing. A committed error writes the target then reports failure. An excursion
writes 7 then the target. A wrong final writes only 7. Missing and delayed runs
perform normal writes and respectively expose no samples or omit the last
sample from the visible history. These two modes model loss at the point where
the observed samples are made visible.
"""

from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic, sleep


_TIMEOUT = 10.0
_POLL_INTERVAL = 0.002
_COMMITTED_ERROR = 4
_MODES = frozenset({
    "normal", "acknowledged_noop", "committed_error", "excursion",
    "wrong_final", "missing", "delayed",
})


def _await_next_poll(deadline: float) -> None:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError("File workflow timed out waiting for its peer")
    sleep(min(_POLL_INTERVAL, remaining))


def _worker(directory: Path, mode: str, target: int) -> int:
    writes = {
        "acknowledged_noop": (),
        "committed_error": (target,),
        "excursion": (7, target),
        "wrong_final": (7,),
    }.get(mode, (1, target))
    deadline = monotonic() + _TIMEOUT
    pending = directory / "pending"
    for step, value in enumerate(writes, 1):
        pending.write_bytes(f"{value}\n".encode("ascii"))
        pending.replace(directory / "state")
        (directory / f"ready-{step}").touch()
        receipt = directory / f"read-{step}"
        while not receipt.exists():
            _await_next_poll(deadline)
    return _COMMITTED_ERROR if mode == "committed_error" else 0


def run_file_workflow(mode: str, target: int) -> tuple[bool, list[int], list[int]]:
    """Run one bounded subprocess workflow and return acknowledgement and samples."""
    if mode not in _MODES:
        raise ValueError(f"Unknown file workflow mode {mode!r}")
    if type(target) is not int or target not in (3, 4):
        raise ValueError("The file workflow target must be the integer 3 or 4")

    with TemporaryDirectory(prefix="guardian-file-") as tmp:
        directory = Path(tmp)
        state = directory / "state"
        state.write_bytes(b"0\n")
        observed = [int(state.read_bytes())]
        deadline = monotonic() + _TIMEOUT
        child = subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).resolve()), tmp, mode, str(target)],
            cwd=directory,
            stdin=subprocess.DEVNULL,
        )
        try:
            while child.poll() is None:
                step = len(observed)
                if (directory / f"ready-{step}").exists():
                    observed.append(int(state.read_bytes()))
                    (directory / f"read-{step}").touch()
                _await_next_poll(deadline)
            if child.returncode not in (0, _COMMITTED_ERROR):
                raise RuntimeError(f"File workflow child exited with code {child.returncode}")
            if int(state.read_bytes()) != observed[-1]:
                raise RuntimeError("Final file content differs from the last observed sample")
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=_TIMEOUT)

        if mode == "missing":
            visible = []
        elif mode == "delayed":
            visible = observed[:-1]
        else:
            visible = observed.copy()
        return child.returncode == 0, observed, visible


if __name__ == "__main__":
    raise SystemExit(_worker(Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])))
