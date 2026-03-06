BUILD ?= build
DESTDIR ?=
prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
systemd_system_unitdir ?= $(libdir)/systemd/system

CFLAGS += -Wall -Wextra -Werror -std=gnu17 -pedantic -O3 -D_GNU_SOURCE

# Enable sanitizers by default
USE_SANITIZER ?= 1
ifeq ($(USE_SANITIZER), 1)
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address -fsanitize=undefined
endif

# Enable clang-tidy checking by default
#USE_CLANG_TIDY ?= 1
#CLANG_TIDY ?= clang-tidy --config-file build-tools/clang-tidy.config


ifeq ($(abspath $(BUILD)),$(shell pwd))
$(error "ERROR: Build dir can't be equal to source dir")
endif

ALL_TARGETS_BIN = container-util image-install install-image-container install-usb-image make-image-container swap-root gpt-insert

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

$(BUILD)/container-util: container-util.c
	mkdir -p $(BUILD)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD)/image-install: image-install.py
	mkdir -p $(BUILD)
	install -m 0755 $< $@

$(BUILD)/install-image-container: install-image-container.sh
	mkdir -p $(BUILD)
	install -m 0755 $< $@

$(BUILD)/install-usb-image: install-usb-image.sh
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

$(BUILD)/%.o: %.c
ifeq ($(USE_CLANG_TIDY), 1)
	$(CLANG_TIDY) $< -- $(CFLAGS)
endif
	mkdir -p $(BUILD)
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
test-su: $(BUILD)/container-util $(BUILD)/install-image-container $(BUILD)/image-install $(BUILD)/make-image-container
	./test-container-su.sh
