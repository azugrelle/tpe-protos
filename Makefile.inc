COMPILER=gcc
COMPILER_FLAGS=-Wall -pedantic -g -pthread -Isrc/shared -Isrc/server
LD_FLAGS=-pthread
# flags del framework `check' usado por los tests (src/test/)
CHECK_FLAGS=$(shell pkg-config --cflags --libs check)
