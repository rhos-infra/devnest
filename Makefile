all: upload test
.PHONY: all test upload

test:
	tox

upload: test
	tox -e upload
