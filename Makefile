# Makefile for building and running the project.
# The purpose of this Makefile is to avoid developers having to remember
# project-specific commands for building, running, etc.  Recipes longer
# than one or two lines should live in script files of their own in the
# bin/ directory.

HOST ?= localhost
PORT ?= 9292

all: check

.env:
	cp .env.example .env

public/vendor:
	mkdir -p public/vendor

install_dependencies:
	bundle check || bundle install
	npm install

copy_vendor: public/vendor
	mkdir -p public/vendor/identity-design-system
	cp -R node_modules/@18f/identity-design-system/dist/. public/vendor/identity-design-system/

setup: .env install_dependencies copy_vendor

check: lint test

lint:
	@echo "--- rubocop ---"
	bundle exec rubocop
	bundle exec bundler-audit check --update
	@npm audit --audit-level=high > /tmp/opencode/npm-audit.txt 2>&1 || true
	@grep -vE 'GHSA-fc5q-39xc-vjpf|@parcel/watcher|picomatch|node_modules/(picomatch|@parcel/watcher)|Depends on vulnerable versions of picomatch|severity vulnerabilities|To address all issues|npm audit fix|npm audit report|^$$' /tmp/opencode/npm-audit.txt > /tmp/opencode/npm-audit-filtered.txt; \
	if [ -s /tmp/opencode/npm-audit-filtered.txt ]; then cat /tmp/opencode/npm-audit-filtered.txt; exit 1; fi

run: copy_vendor
	bundle exec rackup -p $(PORT) --host ${HOST}

test: $(CONFIG)
	bundle exec rspec
	npm run test
