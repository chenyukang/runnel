SHELL := /bin/sh

.DEFAULT_GOAL := help

CARGO ?= cargo
BIN ?= runnel
CONFIG ?= $(HOME)/.config/runnel/config.yaml
LOG_FILE ?= /tmp/runnel.log
ARGS ?=
PERF_BENCH ?= mode_perf
PERF_TARGET_DIR ?= target/perf

RUNNEL_PERF_MODES ?= native-http,native-mux,daze-ashe,daze-baboon,daze-czar,wg
RUNNEL_PERF_WG_PROFILES ?= all
RUNNEL_PERF_WARMUP ?= 100
RUNNEL_PERF_REQUESTS ?= 1000
RUNNEL_PERF_LARGE_DOWNLOADS ?= 8
RUNNEL_PERF_LARGE_BYTES ?= 1048576
RUNNEL_PERF_WG_CLIENT_IP ?= 10.88.0.2
RUNNEL_PERF_WG_SERVER_IP ?= 10.88.0.1
RUNNEL_PERF_WG_MTU ?= 1420
RUNNEL_PERF_WG_READY_TIMEOUT ?= 15
RUNNEL_PERF_WG_CLIENT_DEVICE ?=
RUNNEL_PERF_WG_SERVER_DEVICE ?=
RUNNEL_PERF_LOG ?=

.PHONY: help check test test-all fmt fmt-check clippy ci build release install clean run client server wg-client wg-server wg-config perf perf-wg perf-obfs perf-quick perf-root-check perf-build

help:
	@echo "Targets:"
	@echo "  make check        Run cargo check --all-targets."
	@echo "  make test         Run cargo test."
	@echo "  make test-all     Run cargo test --all-targets --all-features."
	@echo "  make fmt          Format Rust code."
	@echo "  make fmt-check    Check Rust formatting."
	@echo "  make clippy       Run clippy with warnings denied."
	@echo "  make ci           Run fmt-check, clippy, and test-all."
	@echo "  make build        Build debug binary."
	@echo "  make release      Build release binary."
	@echo "  make install      Install the crate from this checkout."
	@echo "  make clean        Remove Cargo build artifacts."
	@echo "  make run ARGS='--help'"
	@echo "  make client ARGS='--help'"
	@echo "  make server ARGS='--help'"
	@echo "  sudo make wg-client ARGS='--dry-run'"
	@echo "  sudo make wg-server ARGS='--dry-run'"
	@echo "  sudo make perf    Run the full local performance benchmark, including WG profiles."
	@echo ""
	@echo "Useful overrides:"
	@echo "  make run CONFIG=~/.config/runnel/config.yaml ARGS='status'"
	@echo "  sudo make perf RUNNEL_PERF_MODES=wg"
	@echo "  sudo make perf RUNNEL_PERF_WG_PROFILES=noise,mask"
	@echo "  sudo make perf RUNNEL_PERF_REQUESTS=500 RUNNEL_PERF_LARGE_BYTES=4194304"

check:
	$(CARGO) check --all-targets

test:
	$(CARGO) test

test-all:
	$(CARGO) test --all-targets --all-features

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

ci: fmt-check clippy test-all

build:
	$(CARGO) build

release:
	$(CARGO) build --release --locked

install:
	$(CARGO) install --path . --locked

clean:
	$(CARGO) clean

run:
	$(CARGO) run --bin $(BIN) -- --config "$(CONFIG)" --log-file "$(LOG_FILE)" $(ARGS)

client:
	$(CARGO) run --bin $(BIN) -- --config "$(CONFIG)" --log-file "$(LOG_FILE)" client $(ARGS)

server:
	$(CARGO) run --bin $(BIN) -- --config "$(CONFIG)" --log-file "$(LOG_FILE)" server $(ARGS)

wg-client:
	$(CARGO) run --bin $(BIN) -- --config "$(CONFIG)" --log-file "$(LOG_FILE)" wg-client $(ARGS)

wg-server:
	$(CARGO) run --bin $(BIN) -- --config "$(CONFIG)" --log-file "$(LOG_FILE)" wg-server $(ARGS)

wg-config:
	$(CARGO) run --bin $(BIN) -- wg-config $(ARGS)

perf-quick:
	$(MAKE) perf RUNNEL_PERF_WARMUP=10 RUNNEL_PERF_REQUESTS=100 RUNNEL_PERF_LARGE_DOWNLOADS=2 RUNNEL_PERF_LARGE_BYTES=1048576

perf-wg:
	$(MAKE) perf RUNNEL_PERF_MODES=wg

perf-obfs:
	$(MAKE) perf RUNNEL_PERF_MODES=wg RUNNEL_PERF_WG_PROFILES=noise,mask,stealth

perf: perf-root-check perf-build
	@BENCH_BIN=$$(find $(PERF_TARGET_DIR)/release/deps -type f -perm -111 -name '$(PERF_BENCH)-*' | sort | tail -n 1); \
	if [ -z "$$BENCH_BIN" ]; then \
		echo "error: failed to locate $(PERF_TARGET_DIR)/release/deps/$(PERF_BENCH)-*"; \
		exit 1; \
	fi; \
	LOG_ENV=; \
	if [ -n "$(RUNNEL_PERF_LOG)" ]; then \
		LOG_ENV="RUNNEL_PERF_LOG=$(RUNNEL_PERF_LOG)"; \
	fi; \
	echo "running $$BENCH_BIN"; \
	env \
		RUNNEL_PERF_MODES="$(RUNNEL_PERF_MODES)" \
		RUNNEL_PERF_WG_PROFILES="$(RUNNEL_PERF_WG_PROFILES)" \
		RUNNEL_PERF_WARMUP="$(RUNNEL_PERF_WARMUP)" \
		RUNNEL_PERF_REQUESTS="$(RUNNEL_PERF_REQUESTS)" \
		RUNNEL_PERF_LARGE_DOWNLOADS="$(RUNNEL_PERF_LARGE_DOWNLOADS)" \
		RUNNEL_PERF_LARGE_BYTES="$(RUNNEL_PERF_LARGE_BYTES)" \
		RUNNEL_PERF_WG_CLIENT_IP="$(RUNNEL_PERF_WG_CLIENT_IP)" \
		RUNNEL_PERF_WG_SERVER_IP="$(RUNNEL_PERF_WG_SERVER_IP)" \
		RUNNEL_PERF_WG_MTU="$(RUNNEL_PERF_WG_MTU)" \
		RUNNEL_PERF_WG_READY_TIMEOUT="$(RUNNEL_PERF_WG_READY_TIMEOUT)" \
		RUNNEL_PERF_WG_CLIENT_DEVICE="$(RUNNEL_PERF_WG_CLIENT_DEVICE)" \
		RUNNEL_PERF_WG_SERVER_DEVICE="$(RUNNEL_PERF_WG_SERVER_DEVICE)" \
		$$LOG_ENV \
		"$$BENCH_BIN"

perf-root-check:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "error: perf creates WG TUN devices and needs root"; \
		echo "run: sudo make perf"; \
		exit 1; \
	fi

perf-build:
	@if [ "$$(id -u)" -eq 0 ] && [ -n "$$SUDO_USER" ]; then \
		BUILD_HOME=$$(eval echo "~$$SUDO_USER"); \
		echo "building $(PERF_BENCH) bench as $$SUDO_USER"; \
		sudo -u "$$SUDO_USER" env HOME="$$BUILD_HOME" $(CARGO) bench --target-dir $(PERF_TARGET_DIR) --bench $(PERF_BENCH) --no-run; \
	else \
		echo "building $(PERF_BENCH) bench"; \
		$(CARGO) bench --target-dir $(PERF_TARGET_DIR) --bench $(PERF_BENCH) --no-run; \
	fi
