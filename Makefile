PYTHON ?= python3
DRS ?= $(PYTHON) -m drs
COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo docker compose || echo docker-compose)

.PHONY: install lint test demo

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	ruff check src tests examples demo
	ruff format --check src tests examples demo
	mypy

test:
	pytest

demo:
	$(PYTHON) demo/prepare.py
	$(COMPOSE) -f demo/docker-compose.yml up -d --wait
	mkdir -p demo/out
	set -a; . demo/customer.env; set +a; \
	env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u ALL_PROXY -u all_proxy \
		$(DRS) scan --config demo/drs.yaml \
		--html demo/out/report.html \
		--json demo/out/report.json \
		--sarif demo/out/report.sarif; \
	code=$$?; \
	$(COMPOSE) -f demo/docker-compose.yml down; \
	exit $$code
