# Makefile for building and running the project.
# The purpose of this Makefile is to avoid developers having to remember
# project-specific commands for building, running, etc.  Recipes longer
# than one or two lines should live in script files of their own in the
# bin/ directory.

PORT ?= 9292

all: check

setup:
	bundle check || bundle install
	[ -f .env ] && echo ".env exists" || cat .env.example >> .env

.env: setup

check: lint test

lint:
	@echo "--- rubocop ---"
	bundle exec rubocop
	@echo "--- reek ---"
	bundle exec reek

run:
	bundle exec rackup -p $(PORT)

test: .env $(CONFIG)
	bundle exec rspec
