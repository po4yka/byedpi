TARGET = ciadpi

CPPFLAGS = -D_DEFAULT_SOURCE
CFLAGS += -I. -std=c99 -O2 -Wall -Wno-unused -Wextra -Wno-unused-parameter -pedantic
WIN_LDFLAGS = -lws2_32 -lmswsock
PYTHON ?= python3
CLANG ?= clang
CARGO ?= cargo
SAN_FLAGS = -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined
FUZZ_FLAGS = -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined
RUST_BIN := target/debug/ciadpi-rs

HEADERS = conev.h desync.h error.h extend.h kavl.h mpool.h packets.h params.h proxy.h win_service.h
SRC = packets.c main.c conev.c proxy.c desync.c mpool.c extend.c
WIN_SRC = win_service.c

OBJ = $(SRC:.c=.o)
WIN_OBJ = $(WIN_SRC:.c=.o)
TEST_DIR := tests
TEST_BIN_DIR := $(TEST_DIR)/bin
PACKETS_CORPUS_DIR := $(TEST_DIR)/corpus/packets
PACKETS_CORPUS_STAMP := $(PACKETS_CORPUS_DIR)/.stamp
PACKETS_TEST_BIN := $(TEST_BIN_DIR)/test_packets
PACKETS_TEST_SAN_BIN := $(TEST_BIN_DIR)/test_packets-sanitize
FUZZ_PACKETS_BIN := $(TEST_BIN_DIR)/fuzz_packets
ORACLE_COMMON_SRC := $(TEST_DIR)/oracle_common.c
ORACLE_PACKETS_BIN := $(TEST_BIN_DIR)/oracle_packets
ORACLE_CONFIG_BIN := $(TEST_BIN_DIR)/oracle_config
ORACLE_PROTOCOL_BIN := $(TEST_BIN_DIR)/oracle_protocol
ORACLE_DESYNC_BIN := $(TEST_BIN_DIR)/oracle_desync
ORACLE_BINS := $(ORACLE_PACKETS_BIN) $(ORACLE_CONFIG_BIN) $(ORACLE_PROTOCOL_BIN) $(ORACLE_DESYNC_BIN)
SAN_TARGET := $(TARGET)-sanitize
SAN_OBJ_DIR := $(TEST_BIN_DIR)/sanitize
SAN_OBJ := $(addprefix $(SAN_OBJ_DIR)/,$(SRC:.c=.o))

PREFIX := /usr/local
INSTALL_DIR := $(DESTDIR)$(PREFIX)/bin/

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LDFLAGS)

windows: $(OBJ) $(WIN_OBJ)
	$(CC) -o $(TARGET).exe $(OBJ) $(WIN_OBJ) $(WIN_LDFLAGS)

$(OBJ): $(HEADERS)
.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

$(PACKETS_CORPUS_STAMP): $(TEST_DIR)/generate_packets_corpus.py
	mkdir -p $(PACKETS_CORPUS_DIR)
	$(PYTHON) $(TEST_DIR)/generate_packets_corpus.py $(PACKETS_CORPUS_DIR)
	touch $(PACKETS_CORPUS_STAMP)

$(PACKETS_TEST_BIN): $(TEST_DIR)/test_packets.c $(TEST_DIR)/packets_exercise.c $(TEST_DIR)/packets_exercise.h packets.c packets.h
	mkdir -p $(TEST_BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(TEST_DIR) $(TEST_DIR)/test_packets.c $(TEST_DIR)/packets_exercise.c packets.c -o $(PACKETS_TEST_BIN)

$(PACKETS_TEST_SAN_BIN): $(TEST_DIR)/test_packets.c $(TEST_DIR)/packets_exercise.c $(TEST_DIR)/packets_exercise.h packets.c packets.h
	mkdir -p $(TEST_BIN_DIR)
	$(CLANG) $(CPPFLAGS) $(SAN_FLAGS) -I. -I$(TEST_DIR) $(TEST_DIR)/test_packets.c $(TEST_DIR)/packets_exercise.c packets.c -o $(PACKETS_TEST_SAN_BIN)

$(SAN_OBJ_DIR)/%.o: %.c $(HEADERS)
	mkdir -p $(dir $@)
	$(CLANG) $(CPPFLAGS) $(SAN_FLAGS) -c $< -o $@

$(SAN_TARGET): $(SAN_OBJ)
	$(CLANG) $(SAN_FLAGS) -o $(SAN_TARGET) $(SAN_OBJ) $(LDFLAGS)

$(FUZZ_PACKETS_BIN): $(TEST_DIR)/fuzz_packets.c $(TEST_DIR)/packets_exercise.c $(TEST_DIR)/packets_exercise.h packets.c packets.h
	mkdir -p $(TEST_BIN_DIR)
	$(CLANG) $(CPPFLAGS) $(FUZZ_FLAGS) -DTEST_STANDALONE_FUZZ -I. -I$(TEST_DIR) $(TEST_DIR)/fuzz_packets.c $(TEST_DIR)/packets_exercise.c packets.c -o $(FUZZ_PACKETS_BIN)

$(ORACLE_PACKETS_BIN): $(TEST_DIR)/oracle_packets.c $(ORACLE_COMMON_SRC) $(PACKETS_CORPUS_STAMP) packets.c packets.h
	mkdir -p $(TEST_BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(TEST_DIR) $(TEST_DIR)/oracle_packets.c $(ORACLE_COMMON_SRC) packets.c -o $(ORACLE_PACKETS_BIN)

$(ORACLE_CONFIG_BIN): $(TEST_DIR)/oracle_config.c $(ORACLE_COMMON_SRC) $(SRC) $(HEADERS) app.h
	mkdir -p $(TEST_BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DCIADPI_NO_MAIN -I$(TEST_DIR) $(TEST_DIR)/oracle_config.c $(ORACLE_COMMON_SRC) $(SRC) -o $(ORACLE_CONFIG_BIN)

$(ORACLE_PROTOCOL_BIN): $(TEST_DIR)/oracle_protocol.c $(ORACLE_COMMON_SRC) $(SRC) $(HEADERS)
	mkdir -p $(TEST_BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DCIADPI_NO_MAIN -I$(TEST_DIR) $(TEST_DIR)/oracle_protocol.c $(ORACLE_COMMON_SRC) $(SRC) -o $(ORACLE_PROTOCOL_BIN)

$(ORACLE_DESYNC_BIN): $(TEST_DIR)/oracle_desync.c $(ORACLE_COMMON_SRC) $(SRC) $(HEADERS) app.h
	mkdir -p $(TEST_BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DCIADPI_NO_MAIN -DCIADPI_TESTING -I$(TEST_DIR) $(TEST_DIR)/oracle_desync.c $(ORACLE_COMMON_SRC) $(SRC) -o $(ORACLE_DESYNC_BIN)

oracles: $(ORACLE_BINS)

packets-corpus: $(PACKETS_CORPUS_STAMP)

test-packets: $(PACKETS_CORPUS_STAMP) $(PACKETS_TEST_BIN)
	$(PACKETS_TEST_BIN) $(PACKETS_CORPUS_DIR)

test-integration: $(TARGET)
	$(PYTHON) $(TEST_DIR)/test_proxy_integration.py --binary ./$(TARGET)

test-desync-runtime: $(TARGET) oracles packets-corpus
	$(PYTHON) $(TEST_DIR)/test_desync_runtime.py --binary ./$(TARGET) --bin-dir ./$(TEST_BIN_DIR) --project-root .

test-auto-runtime: $(TARGET)
	$(PYTHON) $(TEST_DIR)/test_auto_runtime.py --binary ./$(TARGET)

test-linux-routed-runtime: $(TARGET)
	$(PYTHON) $(TEST_DIR)/test_linux_routed_runtime.py --binary ./$(TARGET) --project-root .

test-linux-runtime-features: $(TARGET)
	$(PYTHON) $(TEST_DIR)/test_linux_runtime_features.py --binary ./$(TARGET)

test-contract: $(TARGET) oracles packets-corpus
	$(PYTHON) $(TEST_DIR)/test_contract.py --binary ./$(TARGET) --bin-dir ./$(TEST_BIN_DIR) --project-root .

test-rust: oracles packets-corpus Cargo.toml
	$(CARGO) test --workspace

rust-bin: Cargo.toml
	$(CARGO) build -p ciadpi-bin

test-rust-binary-parity: $(TARGET) rust-bin
	$(PYTHON) $(TEST_DIR)/test_rust_binary_parity.py --c-binary ./$(TARGET) --rust-binary ./$(RUST_BIN)

test-rust-desync-runtime: rust-bin oracles packets-corpus
	$(PYTHON) $(TEST_DIR)/test_desync_runtime.py --binary ./$(RUST_BIN) --bin-dir ./$(TEST_BIN_DIR) --project-root .

test-rust-auto-runtime: rust-bin
	$(PYTHON) $(TEST_DIR)/test_auto_runtime.py --binary ./$(RUST_BIN)

test-rust-linux-routed-runtime: rust-bin
	$(PYTHON) $(TEST_DIR)/test_linux_routed_runtime.py --binary ./$(RUST_BIN) --project-root .

test-rust-linux-runtime-features: rust-bin
	$(PYTHON) $(TEST_DIR)/test_linux_runtime_features.py --binary ./$(RUST_BIN)

test-rust-runtime: rust-bin
	$(PYTHON) $(TEST_DIR)/test_rust_runtime_subset.py --binary ./$(RUST_BIN)

test-rust-runtime-migration: rust-bin
	$(PYTHON) $(TEST_DIR)/test_rust_runtime_migration.py --binary ./$(RUST_BIN)

bench-smoke: oracles packets-corpus Cargo.toml
	$(CARGO) test -p ciadpi-packets benchmark_smoke -- --ignored --nocapture

test: test-packets test-contract test-integration test-desync-runtime test-auto-runtime test-linux-routed-runtime test-linux-runtime-features test-rust test-rust-binary-parity test-rust-desync-runtime test-rust-auto-runtime test-rust-linux-routed-runtime test-rust-linux-runtime-features test-rust-runtime test-rust-runtime-migration

test-sanitize: $(PACKETS_CORPUS_STAMP) $(PACKETS_TEST_SAN_BIN) $(SAN_TARGET) oracles
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 $(PACKETS_TEST_SAN_BIN) $(PACKETS_CORPUS_DIR)
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 $(PYTHON) $(TEST_DIR)/test_proxy_integration.py --binary ./$(SAN_TARGET)
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 $(PYTHON) $(TEST_DIR)/test_desync_runtime.py --binary ./$(SAN_TARGET) --bin-dir ./$(TEST_BIN_DIR) --project-root .
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 $(PYTHON) $(TEST_DIR)/test_auto_runtime.py --binary ./$(SAN_TARGET)
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 $(PYTHON) $(TEST_DIR)/test_contract.py --binary ./$(SAN_TARGET) --bin-dir ./$(TEST_BIN_DIR) --project-root .

fuzz-packets: $(PACKETS_CORPUS_STAMP) $(FUZZ_PACKETS_BIN)
	ASAN_OPTIONS=detect_leaks=0 $(FUZZ_PACKETS_BIN) $(PACKETS_CORPUS_DIR)

clean:
	rm -f $(TARGET) $(SAN_TARGET) $(TARGET).exe $(OBJ) $(WIN_OBJ) $(SAN_OBJ) $(PACKETS_TEST_BIN) $(PACKETS_TEST_SAN_BIN) $(FUZZ_PACKETS_BIN) $(ORACLE_BINS)
	rm -rf $(TEST_BIN_DIR)
	rm -f $(PACKETS_CORPUS_STAMP) $(PACKETS_CORPUS_DIR)/*.bin
	rm -rf target

install: $(TARGET)
	mkdir -p $(INSTALL_DIR)
	install -m 755 $(TARGET) $(INSTALL_DIR)

.PHONY: all windows clean install oracles packets-corpus rust-bin test-packets test-contract test-integration test-desync-runtime test-auto-runtime test-linux-routed-runtime test-linux-runtime-features test-rust test-rust-binary-parity test-rust-desync-runtime test-rust-auto-runtime test-rust-linux-routed-runtime test-rust-linux-runtime-features test-rust-runtime test-rust-runtime-migration bench-smoke test test-sanitize fuzz-packets
