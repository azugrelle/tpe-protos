include ./Makefile.inc

# echoWithSelector.c es el echo standalone (tiene su propio main()): se
# excluye del binario `server' para no chocar con src/server/main.c.
SERVER_SOURCES=$(filter-out src/server/echoWithSelector.c, \
               $(wildcard src/server/*.c) $(wildcard src/server/states/*.c) \
               $(wildcard src/server/parsers/*.c) $(wildcard src/server/utils/*.c))
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
      $(TEST_FOLDER)/request_parser_test \
      $(TEST_FOLDER)/state_connect_test \
      $(TEST_FOLDER)/state_copy_test \
      $(TEST_FOLDER)/state_auth_test \
      $(TEST_FOLDER)/state_request_test \
      $(TEST_FOLDER)/metrics_test \
      $(TEST_FOLDER)/hashmap_user_auth_test

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
$(TEST_FOLDER)/request_parser_test: src/test/request_parser_test.c src/server/parsers/request_parser.c src/shared/buffer.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) src/test/request_parser_test.c src/shared/buffer.c $(CHECK_FLAGS) -o $@

# state_connect_test incluye state_connect.c inline y NO linkea selector.c: el
# harness satisface con stubs propios los símbolos externos del módulo. Se
# interceptan con --wrap connect() y getsockopt() (scriptear el reintento de
# candidatos, inmediato y vía SO_ERROR), freeaddrinfo() (listas armadas a mano
# que no son liberables, y assertar liberación única) y pthread_create()
# (forzar su fallo y correr el worker de DNS sincrónicamente).
$(TEST_FOLDER)/state_connect_test: src/test/state_connect_test.c src/server/states/state_connect.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Wl,--wrap=connect,--wrap=getsockopt,--wrap=freeaddrinfo,--wrap=pthread_create src/test/state_connect_test.c $(CHECK_FLAGS) -o $@

# state_copy_test incluye state_copy.c inline y NO linkea selector.c (stubs
# propios); buffer.c y metrics.c se linkean reales. recv()/send() se
# interceptan con --wrap para inyectar errno, y shutdown() para contar
# propagaciones del FIN e inyectar sus fallos.
$(TEST_FOLDER)/state_copy_test: src/test/state_copy_test.c src/server/states/state_copy.c src/shared/buffer.c src/shared/metrics.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Wl,--wrap=recv,--wrap=send,--wrap=shutdown src/test/state_copy_test.c src/shared/buffer.c src/shared/metrics.c $(CHECK_FLAGS) -o $@

# state_auth_test incluye state_auth.c inline (stubs de request_start /
# check_if_valid_credentials / selector); auth_parser.c y buffer.c se linkean
# reales. Cubre el subnegotiation, incluidos bytes pipelineados con el hello.
$(TEST_FOLDER)/state_auth_test: src/test/state_auth_test.c src/server/states/state_auth.c src/server/parsers/auth_parser.c src/shared/buffer.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) src/test/state_auth_test.c src/server/parsers/auth_parser.c src/shared/buffer.c $(CHECK_FLAGS) -o $@

# state_request_test incluye state_request.c inline (stubs de connect_start /
# copy_start / selector); send() se intercepta con --wrap para forzar envíos
# parciales del reply.
$(TEST_FOLDER)/state_request_test: src/test/state_request_test.c src/server/states/state_request.c src/server/parsers/request_parser.c src/shared/buffer.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Wl,--wrap=send src/test/state_request_test.c src/server/parsers/request_parser.c src/shared/buffer.c $(CHECK_FLAGS) -o $@

# metrics_test incluye metrics.c inline
$(TEST_FOLDER)/metrics_test: src/test/metrics_test.c src/shared/metrics.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) src/test/metrics_test.c $(CHECK_FLAGS) -o $@

# hashmap_user_auth_test incluye hashmap.c y user_auth_utils.c inline
$(TEST_FOLDER)/hashmap_user_auth_test: src/test/hashmap_user_auth_test.c src/server/utils/hashmap.c src/server/utils/user_auth_utils.c
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) src/test/hashmap_user_auth_test.c $(CHECK_FLAGS) -o $@
# Tests de integracion end-to-end (procesos reales, ver su README). Cada
# script es autosuficiente; aca se cablean los que corren estables en
# cualquier entorno.
integration-test: all
	src/test/integration/monitor_session.sh

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

.PHONY: all server client test integration-test clean
