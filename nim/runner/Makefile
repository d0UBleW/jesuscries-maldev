BIN=runner.exe
SRC=runner.nim
NIMFLAGS=-d=mingw -d=release
SSLFLAGS=--passC:"-I/opt/openssl-111w-mingw64/include/" --passL:"-L/opt/openssl-111w-mingw64/lib/" --dynlibOverride:crypto- --dynlibOverride:ssl- --passl:-lssl --passl:-lcrypto --passl:-lws2_32 --passl:-static -d:noOpenSSLHacks -d:ssl -d:sslVersion:'(' -d:nimDisableCertificateValidation

.PHONY: clean

build: $(BIN)

clean:
	rm -f $(BIN)

rebuild: clean build

$(BIN): $(SRC)
	nim c --app=console $(NIMFLAGS) $(SSLFLAGS) --cpu=amd64 $<
