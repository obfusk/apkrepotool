SHELL   := /bin/bash
PYTHON  ?= python3

export PYTHONWARNINGS := default

.PHONY: all install test test-cli test-repo doctest lint lint-extra clean cleanup

all:

install:
	$(PYTHON) -mpip install -e .

test: test-cli doctest lint lint-extra

test-cli:
	# TODO
	apkrepotool --version

test-repo:
	cd test/test-repo && $(MAKE) clean && apkrepotool update -v
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
	cd test/test-repo && apkrepotool update -v
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

doctest:
	APKREPOTOOL_DIR=.tmp $(PYTHON) -m doctest apkrepotool/*.py

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
	rm -fr build/ dist/ .tmp/

.PHONY: _package _publish

_package:
	SOURCE_DATE_EPOCH="$$( git log -1 --pretty=%ct )" \
	  $(PYTHON) setup.py sdist bdist_wheel
	twine check dist/*

_publish: cleanup _package
	read -r -p "Are you sure? "; \
	[[ "$$REPLY" == [Yy]* ]] && twine upload dist/*
