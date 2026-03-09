TARGET = ciadpi

CPPFLAGS = -D_DEFAULT_SOURCE
CFLAGS += -I. -std=c99 -O2 -Wall -Wno-unused -Wextra -Wno-unused-parameter -pedantic
PYTHON ?= python3
CLANG ?= $(or $(shell command -v clang 2>/dev/null),$(shell command -v cc 2>/dev/null),$(CC))
CARGO ?= cargo
FUZZ_FLAGS = -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined
RUST_BIN := target/debug/ciadpi
WINDOWS_TARGET ?= x86_64-pc-windows-gnu
RUST_WINDOWS_BIN := target/$(WINDOWS_TARGET)/debug/ciadpi.exe

TEST_DIR := tests
TEST_BIN_DIR := $(TEST_DIR)/bin
PACKETS_CORPUS_DIR := $(TEST_DIR)/corpus/packets
PACKETS_CORPUS_STAMP := $(PACKETS_CORPUS_DIR)/.stamp
PACKETS_TEST_BIN := $(TEST_BIN_DIR)/test_packets
FUZZ_PACKETS_BIN := $(TEST_BIN_DIR)/fuzz_packets

PREFIX := /usr/local
INSTALL_DIR := $(DESTDIR)$(PREFIX)/bin/

all: $(TARGET)

$(TARGET): FORCE Cargo.toml
	$(CARGO) build -p ciadpi-bin
	install -m 755 $(RUST_BIN) $(TARGET)

windows: FORCE Cargo.toml
	$(CARGO) build -p ciadpi-bin --target $(WINDOWS_TARGET)
	install -m 755 $(RUST_WINDOWS_BIN) $(TARGET).exe

$(PACKETS_CORPUS_STAMP): $(TEST_DIR)/generate_packets_corpus.py
	mkdir -p $(PACKETS_CORPUS_DIR)
	$(PYTHON) $(TEST_DIR)/generate_packets_corpus.py $(PACKETS_CORPUS_DIR)
	touch $(PACKETS_CORPUS_STAMP)

$(PACKETS_TEST_BIN): $(TEST_DIR)/test_packets.c $(TEST_DIR)/packets_exercise.c $(TEST_DIR)/packets_exercise.h packets.c packets.h
	mkdir -p $(TEST_BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(TEST_DIR) $(TEST_DIR)/test_packets.c $(TEST_DIR)/packets_exercise.c packets.c -o $(PACKETS_TEST_BIN)

$(FUZZ_PACKETS_BIN): $(TEST_DIR)/fuzz_packets.c $(TEST_DIR)/packets_exercise.c $(TEST_DIR)/packets_exercise.h packets.c packets.h
	mkdir -p $(TEST_BIN_DIR)
	$(CLANG) $(CPPFLAGS) $(FUZZ_FLAGS) -DTEST_STANDALONE_FUZZ -I. -I$(TEST_DIR) $(TEST_DIR)/fuzz_packets.c $(TEST_DIR)/packets_exercise.c packets.c -o $(FUZZ_PACKETS_BIN)

packets-corpus: $(PACKETS_CORPUS_STAMP)

test-packets: $(PACKETS_CORPUS_STAMP) $(PACKETS_TEST_BIN)
	$(PACKETS_TEST_BIN) $(PACKETS_CORPUS_DIR)

test-integration: $(TARGET)
	$(PYTHON) $(TEST_DIR)/test_proxy_integration.py --binary ./$(TARGET)

test-desync-runtime: $(TARGET) packets-corpus
	$(PYTHON) $(TEST_DIR)/test_desync_runtime.py --binary ./$(TARGET) --project-root .

test-auto-runtime: $(TARGET)
	$(PYTHON) $(TEST_DIR)/test_auto_runtime.py --binary ./$(TARGET)

test-linux-routed-runtime: $(TARGET)
	$(PYTHON) $(TEST_DIR)/test_linux_routed_runtime.py --binary ./$(TARGET) --project-root .

test-linux-runtime-features: $(TARGET)
	$(PYTHON) $(TEST_DIR)/test_linux_runtime_features.py --binary ./$(TARGET)

test-rust: test-rust-oracle-diff Cargo.toml
	$(CARGO) test --workspace --lib --bins
	$(CARGO) test -p ciadpi-bin --test cli
	$(CARGO) test -p ciadpi-desync --test action_planning

test-rust-oracle-diff: packets-corpus Cargo.toml
	$(CARGO) test -p ciadpi-config --test oracle_diff
	$(CARGO) test -p ciadpi-session --test oracle_diff
	$(CARGO) test -p ciadpi-desync --test oracle_diff
	$(CARGO) test -p ciadpi-packets --test oracle_diff

rust-bin: $(TARGET)

test-transition-runtime: test-desync-runtime test-linux-routed-runtime

test-rust-desync-runtime: test-desync-runtime

test-rust-auto-runtime: test-auto-runtime

test-rust-linux-routed-runtime: test-linux-routed-runtime

test-rust-linux-runtime-features: test-linux-runtime-features

test-rust-runtime: $(TARGET)
	$(PYTHON) $(TEST_DIR)/test_rust_runtime_subset.py --binary ./$(TARGET)

test-rust-runtime-migration: $(TARGET)
	$(PYTHON) $(TEST_DIR)/test_rust_runtime_migration.py --binary ./$(TARGET)

test-install-cutover: $(TARGET)
	$(PYTHON) $(TEST_DIR)/test_install_cutover.py --project-root . --source-binary ./$(TARGET)

test-windows-cross-check: Cargo.toml
	$(CARGO) test --workspace --no-run --target x86_64-pc-windows-gnu

bench-smoke: packets-corpus Cargo.toml
	$(CARGO) test -p ciadpi-packets benchmark_smoke -- --ignored --nocapture

cutover-gates: test test-install-cutover bench-smoke

transition-runtime-gates: test-transition-runtime

transition-safety-gates: test-rust-safety

test: test-packets test-integration test-auto-runtime test-linux-runtime-features test-rust test-rust-runtime test-rust-runtime-migration

test-rust-safety: $(TARGET) Cargo.toml
	$(CARGO) test -p ciadpi-packets
	$(PYTHON) $(TEST_DIR)/test_proxy_integration.py --binary ./$(TARGET)
	$(PYTHON) $(TEST_DIR)/test_desync_runtime.py --binary ./$(TARGET) --project-root .

fuzz-packets: $(PACKETS_CORPUS_STAMP) $(FUZZ_PACKETS_BIN)
	ASAN_OPTIONS=detect_leaks=0 $(FUZZ_PACKETS_BIN) $(PACKETS_CORPUS_DIR)

clean:
	rm -f $(TARGET) $(TARGET).exe *.o $(PACKETS_TEST_BIN) $(FUZZ_PACKETS_BIN)
	rm -rf $(TEST_BIN_DIR)
	rm -f $(PACKETS_CORPUS_STAMP) $(PACKETS_CORPUS_DIR)/*.bin
	rm -rf target

install: $(TARGET)
	mkdir -p $(INSTALL_DIR)
	install -m 755 $(TARGET) $(INSTALL_DIR)

FORCE:

.PHONY: FORCE all windows clean install packets-corpus rust-bin test-packets test-integration test-desync-runtime test-auto-runtime test-linux-routed-runtime test-linux-runtime-features test-rust test-rust-oracle-diff test-transition-runtime test-rust-desync-runtime test-rust-auto-runtime test-rust-linux-routed-runtime test-rust-linux-runtime-features test-rust-runtime test-rust-runtime-migration test-install-cutover test-windows-cross-check bench-smoke cutover-gates transition-runtime-gates transition-safety-gates test test-rust-safety fuzz-packets
