COMPILER=gcc
COMPILER_FLAGS=-Wall -pedantic -g -Isrc/shared -Isrc/server
LD_FLAGS=
# flags del framework `check' usado por los tests (src/test/)
CHECK_FLAGS=$(shell pkg-config --cflags --libs check)
