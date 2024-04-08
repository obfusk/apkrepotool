SHELL   := /bin/bash
PYTHON  ?= python3

export PYTHONWARNINGS := default

.PHONY: all install test test-cli doctest lint lint-extra clean cleanup

all:

install:
	$(PYTHON) -mpip install -e .

test: test-cli doctest lint lint-extra

test-cli:
	# TODO
	apkrepotool --version

doctest:
	$(PYTHON) -m doctest apkrepotool/*.py

lint:
	flake8 apkrepotool/*.py
	pylint apkrepotool/*.py

lint-extra:
	mypy --strict --disallow-any-unimported apkrepotool/*.py

clean: cleanup
	rm -fr apkrepotool.egg-info/

cleanup:
	find -name '*~' -delete -print
	rm -fr apkrepotool/__pycache__/ .mypy_cache/
	rm -fr build/ dist/

.PHONY: _package _publish

_package:
	SOURCE_DATE_EPOCH="$$( git log -1 --pretty=%ct )" \
	  $(PYTHON) setup.py sdist bdist_wheel
	twine check dist/*

_publish: cleanup _package
	read -r -p "Are you sure? "; \
	[[ "$$REPLY" == [Yy]* ]] && twine upload dist/*
