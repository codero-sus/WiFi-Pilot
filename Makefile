# wifipilot — developer entry points
.PHONY: help install install-web dev test test-fast demo web tools lint clean report \
	ai-status ai-local ai-cloud api-demo bench bench-pcap

PY ?= python3
PIP ?= $(PY) -m pip

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## install the core CLI (needs only rich)
	$(PIP) install -e .

install-web:  ## install with the web UI dependencies
	$(PIP) install -e '.[web]'

dev:  ## install everything including test tooling
	$(PIP) install -e '.[dev]'

test:  ## run the full test suite (~3.5 min, includes a simulated campaign)
	$(PY) -m pytest -q

test-fast:  ## skip the end-to-end campaign test
	$(PY) -m pytest -q --ignore=tests/test_engine_demo.py

demo:  ## run the whole pipeline against the simulated radio
	$(PY) -m wifipilot demo

web:  ## start the web UI in simulation mode
	$(PY) -m wifipilot --demo web --open

tools:  ## show dependency / capability status (and the platform check)
	$(PY) -m wifipilot tools

ai-status:  ## which AI provider is active, is it reachable, how much has it cost
	$(PY) -m wifipilot ai providers --probe
	$(PY) -m wifipilot ai status

ai-local:  ## use local Ollama for the advisor (private, free)
	$(PY) -m wifipilot --provider ollama ai use qwen2.5:7b
	@echo "export OPENROUTER_API_KEY=... to try the cloud provider instead"

api-demo:  ## drive the pipeline from Python (examples/, no radio needed)
	$(PY) examples/triage.py --demo -t 5
	$(PY) examples/handshake_hunt.py --demo --mode quick -d 30 -t 3

ai-cloud:  ## use OpenRouter for the advisor (needs OPENROUTER_API_KEY)
	$(PY) -m wifipilot --provider openrouter --ai-budget 0.50 ai status

bench:  ## run the benchmarks (pcap, crypto, crack, session, planner, web)
	$(PY) benchmarks/bench.py

bench-pcap:  ## just the capture-parsing benchmarks
	$(PY) benchmarks/bench.py pcap crypto

lint:  ## byte-compile everything and check imports
	$(PY) -m compileall -q wifipilot tests
	$(PY) -c "import wifipilot, wifipilot.cli, wifipilot.engine, wifipilot.web.app; print('imports ok')"

report:  ## print how to find the reports of previous sessions
	@echo "sessions live in ./sessions/<id>/ (journal.jsonl + reports/)"
	@echo "loot lives in ./loot/ (handshakes, PMKIDs, WEP dumps)"
	@ls -1 sessions 2>/dev/null || echo "  (no sessions yet)"

clean:  ## remove caches and build artifacts (never touches loot/ or sessions/)
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
