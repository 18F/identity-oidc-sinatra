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
	cp -R node_modules/@uswds/uswds/dist public/vendor/uswds

setup: .env install_dependencies copy_vendor

check: lint test

lint:
	@echo "--- rubocop ---"
	bundle exec rubocop
	bundle exec bundler-audit check --update
	npm audit --audit-level=high

run:
	bundle exec rackup -p $(PORT) --host ${HOST}

test: $(CONFIG)
	bundle exec rspec
	npm run test
