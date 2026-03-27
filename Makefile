BUILD ?= build
DESTDIR ?=
prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
systemd_system_unitdir ?= $(libdir)/systemd/system

# Hide all deprecated symbols up to 3.0.0
OPENSSL_FLAGS = -DOPENSSL_API_COMPAT=30000 -DOPENSSL_NO_DEPRECATED
CFLAGS += -Wall -Wextra -Werror -std=gnu17 -pedantic -O3 -D_GNU_SOURCE $(OPENSSL_FLAGS)

# Disable sanitizers by default
USE_SANITIZER ?= 0
ifeq ($(USE_SANITIZER), 1)
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address -fsanitize=undefined
endif

# Disable clang-tidy checking by default
USE_CLANG_TIDY ?= 0
# Disable cognitive complexity check to prioritize other checks
CLANG_TIDY_CHECKS_LIST = -readability-function-cognitive-complexity
# short identifiers, in moderation, help making C more readable
CLANG_TIDY_CHECKS_LIST += -readability-identifier-length
# difficult to avoid in c
CLANG_TIDY_CHECKS_LIST += -bugprone-easily-swappable-parameters
space := $() $()
comma := ,
CLANG_TIDY_CHECKS ?= $(subst $(space),$(comma),$(CLANG_TIDY_CHECKS_LIST))
CLANG_TIDY ?= clang-tidy --config-file build-tools/clang-tidy.config -checks=$(CLANG_TIDY_CHECKS)

# Add SRC version
SRC_VERSION := $(shell git describe --dirty --always --tags)
CFLAGS += -DSRC_VERSION=$(SRC_VERSION)

# Enable clang-tidy checking by default
#USE_CLANG_TIDY ?= 1
#CLANG_TIDY ?= clang-tidy --config-file build-tools/clang-tidy.config


ifeq ($(abspath $(BUILD)),$(shell pwd))
$(error "ERROR: Build dir can't be equal to source dir")
endif

ALL_TARGETS_BIN = container-util install-image-container make-image-container swap-root gpt-insert

USE_SYSTEMD ?= 1
ifeq ($(USE_SYSTEMD), 1)
	ALL_TARGETS_SYSTEMD += swap-root.service
endif

.PHONY: all $(ALL_TARGETS_BIN)
all: $(ALL_TARGETS_BIN) $(ALL_TARGETS_SYSTEMD)

$(ALL_TARGETS_BIN): %: $(BUILD)/%

$(ALL_TARGETS_SYSTEMD): %: $(BUILD)/%

# Disable implicit shells script rule
%: %.sh

$(BUILD)/container-util: $(addprefix $(BUILD)/src/,container-util.o log.o header.o)
	mkdir -p $(BUILD)
	$(CC) -o $@ $^ $(LDFLAGS) -lcrypto -lcryptsetup

$(BUILD)/install-image-container: install-image-container.sh
	mkdir -p $(BUILD)
	install -m 0755 $< $@

$(BUILD)/make-image-container: make-image-container.sh
	mkdir -p $(BUILD)
	install -m 0755 $< $@

$(BUILD)/swap-root: swap-root.sh
	mkdir -p $(BUILD)
	install -m 0755 $< $@

$(BUILD)/gpt-insert: gpt-insert.py
	mkdir -p $(BUILD)
	install -m 0755 $< $@

$(BUILD)/%.service: %.service.in
	mkdir -p $(BUILD)
	sed \
		-e 's:@BINDIR@:${bindir}:g' \
		$< > $@

$(BUILD)/src/%.o: src/%.c
ifeq ($(USE_CLANG_TIDY), 1)
	$(CLANG_TIDY) $< -- $(CFLAGS)
endif
	mkdir -p $(BUILD)/src
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(BUILD)

# Create prefixed phony targets to allow generic rules for installation
ALL_TARGETS_BIN_INSTALL = $(patsubst %, %.bin.install, $(ALL_TARGETS_BIN))
ALL_TARGETS_SYSTEMD_INSTALL = $(patsubst %, %.systemd.install, $(ALL_TARGETS_SYSTEMD))

.PHONY: install
install: $(ALL_TARGETS_BIN_INSTALL) $(ALL_TARGETS_SYSTEMD_INSTALL)

.PHONY:
%.bin.install: $(BUILD)/%
	install -d $(DESTDIR)$(bindir)
	install -m 0755 $< $(DESTDIR)$(bindir)

.PHONY:
%.systemd.install: $(BUILD)/%
	install -d $(DESTDIR)$(systemd_system_unitdir)
	install -m 0644 $< $(DESTDIR)$(systemd_system_unitdir)

.PHONY: test
test: $(BUILD)/container-util
	./test-container-util.py

.PHONY: test-su
test-su: $(BUILD)/container-util $(BUILD)/install-image-container $(BUILD)/make-image-container $(BUILD)/gpt-insert
	./test-container-su.sh
