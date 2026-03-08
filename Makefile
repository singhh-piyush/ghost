# Ghost Security Components Build
# Requires: gcc, libseccomp-dev (for seccomp)

CC = gcc
CFLAGS = -Wall -O2

LIB_DIR = lib
SECCOMP_SRC = $(LIB_DIR)/apply_seccomp.c
SECCOMP_BIN = $(LIB_DIR)/apply_seccomp
LANDLOCK_SRC = $(LIB_DIR)/apply_landlock.c
LANDLOCK_BIN = $(LIB_DIR)/apply_landlock

.PHONY: all clean install check

all: seccomp landlock

seccomp: $(SECCOMP_BIN)

$(SECCOMP_BIN): $(SECCOMP_SRC)
	@echo "Building seccomp filter..."
	@if pkg-config --exists libseccomp 2>/dev/null; then \
		$(CC) $(CFLAGS) -o $@ $< -lseccomp && echo "  -> $@ built"; \
	else \
		echo "  [SKIP] libseccomp-dev not installed"; \
	fi

landlock: $(LANDLOCK_BIN)

$(LANDLOCK_BIN): $(LANDLOCK_SRC)
	@echo "Building landlock filter..."
	@$(CC) $(CFLAGS) -o $@ $< 2>/dev/null && echo "  -> $@ built" || echo "  [SKIP] Landlock headers not available"

clean:
	rm -f $(SECCOMP_BIN) $(LANDLOCK_BIN)

install: all
	@echo "Security binaries installed to $(LIB_DIR)/"

check:
	@echo "Checking dependencies..."
	@command -v tor >/dev/null && echo "  [OK] tor" || echo "  [MISSING] tor"
	@command -v bpftrace >/dev/null && echo "  [OK] bpftrace" || echo "  [OPTIONAL] bpftrace (for eBPF monitor)"
	@command -v capsh >/dev/null && echo "  [OK] capsh" || echo "  [OPTIONAL] capsh (libcap)"
	@pkg-config --exists libseccomp 2>/dev/null && echo "  [OK] libseccomp" || echo "  [OPTIONAL] libseccomp-dev"
