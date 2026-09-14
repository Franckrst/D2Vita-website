# Byte compatibility of Monocypher 4.0.2 with the contract vectors.
#   make check           verify the vendored sources, build, run
#   make check-sanitize  same with AddressSanitizer and UBSan
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
VECTORS ?= ../../vectors

SOURCES = check_sealed.c d2vseal.c jsonlite.c monocypher.c monocypher-ed25519.c
HEADERS = d2vseal.h jsonlite.h monocypher.h monocypher-ed25519.h
SANITIZE = -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=all

.PHONY: check check-sanitize verify-sources clean

check: verify-sources check_sealed
	./check_sealed $(VECTORS)

check-sanitize: verify-sources check_sealed_sanitize
	./check_sealed_sanitize $(VECTORS)

verify-sources:
	sha256sum --check --ignore-missing --quiet MONOCYPHER_SHA256

check_sealed: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) -lm

check_sealed_sanitize: $(SOURCES) $(HEADERS)
	$(CC) $(SANITIZE) -o $@ $(SOURCES) -lm

clean:
	rm -f check_sealed check_sealed_sanitize
