COMPILER=gcc
COMPILER_FLAGS=-std=c11 -D_POSIX_C_SOURCE=200809L -Wall -pedantic -g -pthread -MMD -MP -Isrc/shared -Isrc/shared/include -Isrc/server
LD_FLAGS=-pthread
# flags del framework `check' usado por los tests (src/test/)
CHECK_FLAGS=$(shell pkg-config --cflags --libs check)
