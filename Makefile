# Configuration.
CARGO_TARGET_DIR	?= $(shell pwd)/../target
# We currently only support absolute paths.
CARGO_TARGET_DIR	:= $(abspath $(CARGO_TARGET_DIR))
SQV	?= $(CARGO_TARGET_DIR)/debug/sqv

# Tools.
CARGO	?= cargo
CODESPELL	?= codespell
CODESPELL_FLAGS ?= --disable-colors --write-changes

ifneq ($(filter Darwin %BSD,$(shell uname -s)),)
	INSTALL		?= ginstall
else
	INSTALL		?= install
endif

# If CARGO_PACKAGES contains a package specification ("-p foo"), then
# only run cargo test.
.PHONY: test check
test check:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) $(CARGO) test $(CARGO_FLAGS) $(CARGO_PACKAGES) $(CARGO_TEST_ARGS)
	$(MAKE) examples

.PHONY: examples
examples:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	    $(CARGO) build $(CARGO_FLAGS) --examples

# Installation.
.PHONY: build-release
build-release:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	    $(CARGO) build $(CARGO_FLAGS) --release --package sequoia-sqv

.PHONY: install
install: build-release
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/bin $(CARGO_TARGET_DIR)/release/sqv
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/zsh/site-functions
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/share/zsh/site-functions \
	    $(CARGO_TARGET_DIR)/_sqv
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions
	$(INSTALL) $(CARGO_TARGET_DIR)/sqv.bash \
	    $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sqv
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/fish/completions
	$(INSTALL) -t $(DESTDIR)$(PREFIX)/share/fish/completions \
	    $(CARGO_TARGET_DIR)/sqv.fish

.PHONY: codespell
codespell:
	$(CODESPELL) $(CODESPELL_FLAGS) \
	  -L "crate,ede,iff,mut,nd,te,uint,KeyServer,keyserver,Keyserver,keyservers,Keyservers,keypair,keypairs,KeyPair,fpr,dedup" \
	  -S "*.bin,*.gpg,*.pgp,./.git,data,highlight.js,*/target,Makefile"
