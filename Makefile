# Makefile for building and running the project.
# The purpose of this Makefile is to avoid developers having to remember
# project-specific commands for building, running, etc.  Recipes longer
# than one or two lines should live in script files of their own in the
# bin/ directory.

HOST ?= localhost
PORT ?= 9393

all: check

.env:
	cp .env.example .env

public/vendor:
	mkdir -p public/vendor

install_dependencies:
	bundle check || bundle install
	npm install

copy_vendor: public/vendor
	cp -R node_modules/@18f/identity-design-system/dist public/vendor/identity-design-system

# Local key material; generated, never committed.
config/rs_demo.key config/rs_demo.crt:
	$(MAKE) --no-print-directory rs_keypair

setup: .env install_dependencies copy_vendor config/rs_demo.key

check: lint test

lint:
	@echo "--- rubocop ---"
	bundle exec rubocop
	bundle exec bundler-audit check --update
	npm audit --audit-level=high

run:
	bundle exec rackup -p $(PORT) --host ${HOST}

test: $(CONFIG) config/rs_demo.key
	bundle exec rspec
	npm run test

# Generate (or regenerate) the resource server key pair (RSA 2048, self-signed,
# 10 years). The same key pair is used for the agency's direct OIDC sign-in, for
# RFC 7523 introspection assertions and for Attempts API decryption. It is
# git-ignored; copy the printed certificate into identity-idp yourself as
# certs/sp/rs_records_demo.crt (ignored there as well).
rs_keypair:
	openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
		-subj "/CN=records-api.agency.localdev" \
		-keyout config/rs_demo.key -out config/rs_demo.crt
	@$(MAKE) --no-print-directory rs_cert

# Print the resource server certificate PEM to paste into the IdP fixture.
rs_cert:
	@echo "# Paste into identity-idp certs/sp/rs_records_demo.crt"
	@cat config/rs_demo.crt
