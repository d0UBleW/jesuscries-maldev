BIN=runner.exe
SRC=runner.nim

NFLAGS  =--app:console
NFLAGS +=--cpu:amd64
NFLAGS +=--d:mingw
NFLAGS +=--d:release
NFLAGS +=--cincludes:/opt/openssl-111w-mingw64/include/
NFLAGS +=--clibdir:/opt/openssl-111w-mingw64/lib/
NFLAGS +=--clib:ssl
NFLAGS +=--clib:crypto
NFLAGS +=--clib:ws2_32
NFLAGS +=--passL:-static
NFLAGS +=--dynlibOverride:crypto-
NFLAGS +=--dynlibOverride:ssl-
NFLAGS +=--d:noOpenSSLHacks
NFLAGS +=--d:ssl
NFLAGS +=--d:sslVersion:'('
NFLAGS +=--d:nimDisableCertificateValidation

.PHONY: clean

build: $(BIN)

clean:
	rm -f $(BIN)

rebuild: clean build

$(BIN): $(SRC)
	nim c $(NFLAGS) $<
