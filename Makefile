SHELL       := /bin/bash
PYTHON      ?= python3

APKREPOTOOL ?= apkrepotool
PYCOV       := $(PYTHON) -mcoverage run --data-file=$(PWD)/.coverage --source $(PWD)/apkrepotool

export PYTHONWARNINGS := default

.PHONY: all install test test-cli doctest coverage test-repo lint lint-extra clean cleanup

all:

install:
	$(PYTHON) -mpip install -e .

test: test-cli doctest lint lint-extra

test-cli:
	# TODO
	$(APKREPOTOOL) --version

doctest:
	APKREPOTOOL_DIR=.tmp $(PYTHON) -m doctest apkrepotool/*.py apkrepotool/hooks/*.py

coverage:
	rm -fr .tmp/
	APKREPOTOOL_DIR=.tmp $(PYCOV) -m doctest apkrepotool/*.py apkrepotool/hooks/*.py
	$(MAKE) test-repo APKREPOTOOL="$(PYCOV) -a -m apkrepotool.__init__"
	$(PYTHON) -mcoverage html --data-file=$(PWD)/.coverage
	$(PYTHON) -mcoverage report --data-file=$(PWD)/.coverage

test-repo:
	cd test/test-repo && $(MAKE) clean && APKREPOTOOL_DIR=.tmp $(APKREPOTOOL) update -v
	diff -Naur \
	  <( jq < test/test-repo-reference-data/entry-1strun.json \
	     | sed -r '/^ *"(timestamp|sha256)":/d' ) \
	  <( jq < test/test-repo/repo/entry.json \
	     | sed -r '/^ *"(timestamp|sha256)":/d' )
	diff -Naur \
	  <( jq < test/test-repo-reference-data/index-v1.json \
	     | sed -r '/^ *"(timestamp|added|lastUpdated)":/d' ) \
	  <( jq < test/test-repo/repo/index-v1.json \
	     | sed -r '/^ *"(timestamp|added|lastUpdated)":/d' )
	diff -Naur \
	  <( jq < test/test-repo-reference-data/index-v2.json \
	     | sed -r '/^ *"(timestamp|added|lastUpdated)":/d' ) \
	  <( jq < test/test-repo/repo/index-v2.json \
	     | sed -r '/^ *"(timestamp|added|lastUpdated)":/d' )
	cd test/test-repo && APKREPOTOOL_DIR=.tmp $(APKREPOTOOL) update -v
	diff -Naur \
	  <( jq < test/test-repo-reference-data/entry-2ndrun.json \
	     | sed -r -e '/^ *"(timestamp|sha256)":/d' \
	              -e 's/"[0-9]+":/"TIMESTAMP":/' \
		      -e 's!diff/[0-9]+!diff/TIMESTAMP!' ) \
	  <( jq < test/test-repo/repo/entry.json \
	     | sed -r -e '/^ *"(timestamp|sha256)":/d' \
	              -e 's/"[0-9]+":/"TIMESTAMP":/' \
		      -e 's!diff/[0-9]+!diff/TIMESTAMP!' )
	diff -Naur \
	  <( jq < test/test-repo-reference-data/index-v1.json \
	     | sed -r '/^ *"(timestamp|added|lastUpdated)":/d' ) \
	  <( jq < test/test-repo/repo/index-v1.json \
	     | sed -r '/^ *"(timestamp|added|lastUpdated)":/d' )
	diff -Naur \
	  <( jq < test/test-repo-reference-data/index-v2.json \
	     | sed -r '/^ *"(timestamp|added|lastUpdated)":/d' ) \
	  <( jq < test/test-repo/repo/index-v2.json \
	     | sed -r '/^ *"(timestamp|added|lastUpdated)":/d' )
	diff -Naur <( cd test/test-repo && APKREPOTOOL_DIR=.tmp $(APKREPOTOOL) link ) \
	  <( printf '%s%s\n' https://example.com/test/repo/?fingerprint= \
	     D79397F1A5615239F6D51DAF4814C56A1B9BE35B08B89CC472D801626D22FE7D )
	diff -Naur <( cd test/test-repo && APKREPOTOOL_DIR=.tmp COLUMNS=80 \
	              $(APKREPOTOOL) --help ) test/test-repo-help
	diff -Naur <( cd test/test-repo && APKREPOTOOL_DIR=.tmp \
	              $(APKREPOTOOL) test | grep -Ev 'diff/|cache/' ) test/test-repo-test

lint:
	flake8 apkrepotool/*.py apkrepotool/hooks/*.py
	pylint apkrepotool/*.py apkrepotool/hooks/*.py

lint-extra:
	mypy --strict --disallow-any-unimported apkrepotool/*.py apkrepotool/hooks/*.py

clean: cleanup
	rm -fr apkrepotool.egg-info/

cleanup:
	find -name '*~' -delete -print
	rm -fr apkrepotool/__pycache__/ apkrepotool/hooks/__pycache__/ .mypy_cache/
	rm -fr build/ dist/ .tmp/ .coverage htmlcov/

.PHONY: _package _publish

_package:
	SOURCE_DATE_EPOCH="$$( git log -1 --pretty=%ct )" \
	  $(PYTHON) setup.py sdist bdist_wheel
	twine check dist/*

_publish: cleanup _package
	read -r -p "Are you sure? "; \
	[[ "$$REPLY" == [Yy]* ]] && twine upload dist/*
