SHELL := /bin/sh

CARGO ?= cargo
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

.PHONY: help perf perf-root-check perf-build

help:
	@echo "Targets:"
	@echo "  sudo make perf    Run the full local performance benchmark, including WG profiles."
	@echo ""
	@echo "Useful overrides:"
	@echo "  sudo make perf RUNNEL_PERF_MODES=wg"
	@echo "  sudo make perf RUNNEL_PERF_WG_PROFILES=noise,mask"
	@echo "  sudo make perf RUNNEL_PERF_REQUESTS=500 RUNNEL_PERF_LARGE_BYTES=4194304"

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
