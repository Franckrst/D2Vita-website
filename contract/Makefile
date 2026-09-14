# D2Vita contract v1 checks. Run from contract/ or with make -C contract.
PYTHON ?= python3
VENV := .venv
VENV_PYTHON := $(VENV)/bin/python

.PHONY: venv test check

venv: $(VENV)/.installed

$(VENV)/.installed: requirements.txt
	$(PYTHON) -m venv --system-site-packages $(VENV)
	$(VENV_PYTHON) -m pip install --quiet -r requirements.txt
	touch $@

test: venv
	$(VENV_PYTHON) -m unittest discover -s tools/tests -t tools

check: test
	$(VENV_PYTHON) tools/gen_vectors.py --check
	$(VENV_PYTHON) tools/check_schemas.py
	$(MAKE) -C tools/c_check check
