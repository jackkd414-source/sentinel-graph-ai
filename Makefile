# Canonical entrypoints. `make test|typecheck|build|verify|release`.
# On Windows use the venv interpreter explicitly: make PY=.venv/Scripts/python.exe

PY      ?= .venv/Scripts/python.exe
PY_LIN  ?= .venv/bin/python
NODE    ?= node
TSC     := frontend/node_modules/typescript/bin/tsc

.PHONY: test typecheck build verify release clean

test:                 ## backend test suite (config from pyproject.toml)
	$(PY) -m pytest

typecheck:            ## TypeScript, no emit
	$(NODE) $(TSC) -b frontend

build:                ## production frontend bundle
	cd frontend && npm run build

verify:               ## end-to-end against a running server
	$(PY) tools/verify.py --skip-ai

release:              ## clean, PII-gated bundle -> release/
	$(PY) tools/make_release.py

clean:
	rm -rf frontend/dist release .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
