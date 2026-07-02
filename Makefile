include ./Makefile.inc

# echoWithSelector.c es el echo standalone de M0 (tiene su propio main()): se
# excluye del binario `server' para no chocar con src/server/main.c.
SERVER_SOURCES=$(filter-out src/server/echoWithSelector.c, \
               $(wildcard src/server/*.c) $(wildcard src/server/states/*.c) \
               $(wildcard src/server/utils/*.c))
CLIENT_SOURCES=$(wildcard src/client/*.c)
SHARED_SOURCES=$(wildcard src/shared/*.c)

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)

OUTPUT_FOLDER=./bin
OBJECTS_FOLDER=./obj

SERVER_OUTPUT_FILE=$(OUTPUT_FOLDER)/server
CLIENT_OUTPUT_FILE=$(OUTPUT_FOLDER)/client

all: client server
server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $(SERVER_OBJECTS) $(SHARED_OBJECTS) -o $(SERVER_OUTPUT_FILE)

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $(CLIENT_OBJECTS) $(SHARED_OBJECTS) -o $(CLIENT_OUTPUT_FILE)

obj/%.o: src/%.c
	mkdir -p $(dir $@)
	$(COMPILER) $(COMPILER_FLAGS) -c $< -o $@

# Tests con el framework `check'. Algunos tests incluyen directamente el .c bajo
# prueba (para acceder a sus funciones internas): en ese caso NO se lo vuelve a
# linkear, solo se linkean sus dependencias.
TEST_FOLDER=$(OUTPUT_FOLDER)/test
TESTS=$(TEST_FOLDER)/buffer_test \
      $(TEST_FOLDER)/selector_test \
      $(TEST_FOLDER)/netutils_test \
      $(TEST_FOLDER)/parser_test \
      $(TEST_FOLDER)/parser_utils_test \
      $(TEST_FOLDER)/stm_test \
      $(TEST_FOLDER)/request_parser_test

test: $(TESTS)
	@for t in $(TESTS); do echo "== $$t =="; $$t || exit 1; done

# buffer_test incluye buffer.c inline
$(TEST_FOLDER)/buffer_test: src/test/buffer_test.c src/shared/buffer.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) src/test/buffer_test.c $(CHECK_FLAGS) -o $@

# selector_test incluye selector.c inline
$(TEST_FOLDER)/selector_test: src/test/selector_test.c src/shared/selector.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) src/test/selector_test.c $(CHECK_FLAGS) -o $@

$(TEST_FOLDER)/netutils_test: src/test/netutils_test.c src/shared/netutils.c src/shared/buffer.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) src/test/netutils_test.c src/shared/netutils.c src/shared/buffer.c $(CHECK_FLAGS) -o $@

$(TEST_FOLDER)/parser_test: src/test/parser_test.c src/shared/parser.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) src/test/parser_test.c src/shared/parser.c $(CHECK_FLAGS) -o $@

$(TEST_FOLDER)/parser_utils_test: src/test/parser_utils_test.c src/shared/parser_utils.c src/shared/parser.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) src/test/parser_utils_test.c src/shared/parser_utils.c src/shared/parser.c $(CHECK_FLAGS) -o $@

$(TEST_FOLDER)/stm_test: src/test/stm_test.c src/shared/stm.c src/shared/selector.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) src/test/stm_test.c src/shared/stm.c src/shared/selector.c $(CHECK_FLAGS) -o $@

# request_parser_test incluye request_parser.c inline
$(TEST_FOLDER)/request_parser_test: src/test/request_parser_test.c src/server/request_parser.c src/shared/buffer.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) src/test/request_parser_test.c src/shared/buffer.c $(CHECK_FLAGS) -o $@

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECT_FOLDER)

.PHONY: all server client test clean
