.PHONY: install test lint typecheck formal check benchmark reproduce verify-reproduce latency sbom package

install:
	python -m pip install --no-deps -r requirements.lock
	python -m pip install --no-deps --no-build-isolation -e .
	python -m pip check

test:
	pytest

lint:
	ruff check src tests experiments scripts formal

typecheck:
	mypy src/guardian_runtime

formal:
	python formal/check_model.py

check: lint typecheck test formal

benchmark:
	python -m experiments.attack_suite

reproduce:
	python -m experiments.run_reference_suite

verify-reproduce:
	cp results/checksums.sha256 /tmp/guardian-checksums.before
	python -m experiments.run_reference_suite
	diff -u /tmp/guardian-checksums.before results/checksums.sha256

latency:
	python -m experiments.latency_benchmark

sbom:
	python scripts/dependency_inventory.py results/dependency_inventory.json
	python scripts/generate_sbom.py results/sbom.spdx.json

package:
	rm -rf dist
	python -m pip wheel . --no-deps --no-build-isolation -w dist
	python scripts/checksum_artifacts.py dist
