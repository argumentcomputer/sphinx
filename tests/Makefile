SHELL := /bin/bash

all:
	@set -e; \
	for dir in */ ; do \
		echo "Building in $${dir}..."; \
		cd $${dir} && cargo prove build || { echo "Failed at command: cd $${dir} && cargo prove build"; exit 1; }; \
		cd ..; \
	done

.PHONY: all
